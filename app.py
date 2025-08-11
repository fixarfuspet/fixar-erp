# -- app.py (tek dosyalık ERP/MES API) --
from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import jwt
from passlib.context import CryptContext
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, ForeignKey, DateTime, Text, select, desc, Table, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship

DB_URL = "sqlite:///./fixar.db"
engine = create_engine(DB_URL, future=True, echo=False, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()
def get_db():
    db=SessionLocal()
    try: yield db
    finally: db.close()

SECRET="fixar-secret"; ALGO="HS256"
pwd=CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer=HTTPBearer(auto_error=False)
def hash_pw(p): return pwd.hash(p)
def verify_pw(p,h): return pwd.verify(p,h)
def make_token(sub): return jwt.encode({"sub":sub,"exp":datetime.utcnow()+timedelta(hours=12)}, SECRET, algorithm=ALGO)
def decode_token(t): return jwt.decode(t, SECRET, algorithms=[ALGO])
def get_user(creds:HTTPAuthorizationCredentials=Depends(bearer), db:Session=Depends(get_db)):
    if not creds: raise HTTPException(401,"Auth required")
    try: u_name=decode_token(creds.credentials).get("sub")
    except Exception: raise HTTPException(401,"Invalid token")
    u=db.execute(select(User).where(User.username==u_name)).scalar_one_or_none()
    if not u or not u.is_active: raise HTTPException(401,"User inactive")
    return u
def require_roles(*roles:str):
    def inner(u:"User"=Depends(get_user)):
        have={r.name for r in u.roles}
        if not roles or (have & set(roles)): return u
        raise HTTPException(403,"Insufficient role")
    return inner

user_roles = Table("user_roles", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    UniqueConstraint("user_id","role_id", name="uq_user_role")
)

class User(Base):
    __tablename__="users"
    id=Column(Integer, primary_key=True)
    username=Column(String, unique=True, nullable=False)
    full_name=Column(String); email=Column(String)
    hashed_password=Column(String, nullable=False)
    is_active=Column(Boolean, default=True)
    roles=relationship("Role", secondary=user_roles, back_populates="users")

class Role(Base):
    __tablename__="roles"
    id=Column(Integer, primary_key=True)
    name=Column(String, unique=True, nullable=False)
    users=relationship("User", secondary=user_roles, back_populates="roles")

class Warehouse(Base):
    __tablename__="warehouses"
    id=Column(Integer, primary_key=True); code=Column(String, unique=True, nullable=False); name=Column(String, nullable=False)

class Item(Base):
    __tablename__="items"
    id=Column(Integer, primary_key=True)
    code=Column(String, unique=True, nullable=False); name=Column(String, nullable=False)
    type=Column(String, nullable=False); unit=Column(String, default="adet")
    vat_rate=Column(Float, default=20.0); min_stock=Column(Float, default=0.0)
    cost_method=Column(String, default="AVERAGE"); barcode=Column(String)

class Party(Base):
    __tablename__="parties"
    id=Column(Integer, primary_key=True); code=Column(String, unique=True, nullable=False)
    name=Column(String, nullable=False); type=Column(String, nullable=False)
    vade_gun=Column(Integer, default=0); risk_limit=Column(Float, default=0.0)

class Stock(Base):
    __tablename__="stocks"
    id=Column(Integer, primary_key=True)
    item_id=Column(Integer, ForeignKey("items.id"), nullable=False)
    warehouse_id=Column(Integer, ForeignKey("warehouses.id"), nullable=False)
    qty=Column(Float, default=0.0); avg_cost=Column(Float, default=0.0)

class StockMove(Base):
    __tablename__="stock_moves"
    id=Column(Integer, primary_key=True)
    ts=Column(DateTime, default=datetime.utcnow, index=True)
    item_id=Column(Integer, ForeignKey("items.id"), nullable=False)
    wh_from=Column(Integer, ForeignKey("warehouses.id")); wh_to=Column(Integer, ForeignKey("warehouses.id"))
    qty=Column(Float, nullable=False); unit_price=Column(Float, default=0.0)
    move_type=Column(String, nullable=False); ref=Column(String)

class Document(Base):
    __tablename__="documents"
    id=Column(Integer, primary_key=True)
    doc_type=Column(String, nullable=False); number=Column(String, unique=True, nullable=False)
    date=Column(DateTime, default=datetime.utcnow); party_id=Column(Integer, ForeignKey("parties.id"), nullable=False)
    currency=Column(String, default="TRY"); notes=Column(Text)
    subtotal=Column(Float, default=0.0); vat_total=Column(Float, default=0.0); grand_total=Column(Float, default=0.0)
    status=Column(String, default="OPEN")

class DocumentLine(Base):
    __tablename__="document_lines"
    id=Column(Integer, primary_key=True)
    document_id=Column(Integer, ForeignKey("documents.id"), nullable=False)
    item_id=Column(Integer, ForeignKey("items.id"), nullable=False)
    qty=Column(Float, nullable=False); unit_price=Column(Float, nullable=False)
    vat_rate=Column(Float, default=20.0); line_total=Column(Float, default=0.0)

class CashAccount(Base):
    __tablename__="cash_accounts"; id=Column(Integer, primary_key=True); name=Column(String, unique=True, nullable=False)

class BankAccount(Base):
    __tablename__="bank_accounts"; id=Column(Integer, primary_key=True); name=Column(String, unique=True, nullable=False); iban=Column(String)

class CashBankTx(Base):
    __tablename__="cash_bank_tx"
    id=Column(Integer, primary_key=True); date=Column(DateTime, default=datetime.utcnow)
    account_type=Column(String, nullable=False); account_id=Column(Integer, nullable=False)
    direction=Column(String, nullable=False); party_id=Column(Integer, ForeignKey("parties.id"))
    amount=Column(Float, nullable=False); currency=Column(String, default="TRY"); ref=Column(String); notes=Column(Text)

class Cheque(Base):
    __tablename__="cheques"
    id=Column(Integer, primary_key=True); number=Column(String, unique=True, nullable=False)
    party_id=Column(Integer, ForeignKey("parties.id")); amount=Column(Float, nullable=False)
    currency=Column(String, default="TRY"); due_date=Column(DateTime, nullable=False); status=Column(String, default="PORTFOY"); notes=Column(Text)

class WorkOrder(Base):
    __tablename__="work_orders"
    id=Column(Integer, primary_key=True); number=Column(String, unique=True, nullable=False)
    product_id=Column(Integer, ForeignKey("items.id"), nullable=False); target_qty=Column(Float, nullable=False)
    produced_qty=Column(Float, default=0.0); start_date=Column(DateTime, default=datetime.utcnow)
    end_date=Column(DateTime); status=Column(String, default="IN_PROGRESS"); notes=Column(Text)

class WorkOrderConsumption(Base):
    __tablename__="wo_consumptions"
    id=Column(Integer, primary_key=True); wo_id=Column(Integer, ForeignKey("work_orders.id"), nullable=False)
    item_id=Column(Integer, ForeignKey("items.id"), nullable=False); qty=Column(Float, nullable=False)
    wh_id=Column(Integer, ForeignKey("warehouses.id"), nullable=False); ref=Column(String)

class WorkOrderFG(Base):
    __tablename__="wo_fg"
    id=Column(Integer, primary_key=True); wo_id=Column(Integer, ForeignKey("work_orders.id"), nullable=False)
    product_id=Column(Integer, ForeignKey("items.id"), nullable=False); qty=Column(Float, nullable=False)
    wh_id=Column(Integer, ForeignKey("warehouses.id"), nullable=False); unit_cost=Column(Float, default=0.0)

# ---- Pydantic ----
class Token(BaseModel): access_token:str; token_type:str="bearer"
class RegisterIn(BaseModel): username:str; password:str; full_name:Optional[str]=None; email:Optional[str]=None; roles:List[str]=[]
class LoginIn(BaseModel): username:str; password:str
class WarehouseIn(BaseModel): code:str; name:str
class ItemIn(BaseModel): code:str; name:str; type:str; unit:str="adet"; vat_rate:float=20.0; min_stock:float=0.0; cost_method:str="AVERAGE"; barcode:Optional[str]=None
class PartyIn(BaseModel): code:str; name:str; type:str; vade_gun:int=0; risk_limit:float=0.0
class StockMoveIn(BaseModel): item_code:str; wh_from_code:Optional[str]=None; wh_to_code:Optional[str]=None; qty:float; unit_price:float=0.0; move_type:str; ref:Optional[str]=None
class DocLineIn(BaseModel): item_code:str; qty:float; unit_price:float; vat_rate:float=20.0
class DocumentIn(BaseModel): doc_type:str; number:Optional[str]=None; party_code:str; currency:str="TRY"; notes:Optional[str]=None; lines:List[DocLineIn]
class CashBankCreate(BaseModel): account_type:str; name:str; iban:Optional[str]=None
class TxCreate(BaseModel): account_type:str; account_name:str; direction:str; party_code:Optional[str]=None; amount:float; currency:str="TRY"; ref:Optional[str]=None; notes:Optional[str]=None
class ChequeCreate(BaseModel): number:str; party_code:Optional[str]=None; amount:float; currency:str="TRY"; due_date:datetime; status:str="PORTFOY"; notes:Optional[str]=None
class WOCreate(BaseModel): product_code:str; target_qty:float; notes:Optional[str]=None
class WOConsumeIn(BaseModel): wo_id:int; item_code:str; qty:float; warehouse_code:str; ref:Optional[str]=None
class WOProduceIn(BaseModel): wo_id:int; qty:float; warehouse_code:str; overhead_rate:float=0.0

app=FastAPI(title="Fixar ERP/MES (TR, TL)")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
Base.metadata.create_all(bind=engine)

@app.get("/health")
def health(): return {"status":"ok"}

def next_number(db:Session, doc_type:str)->str:
    prefix={"QUOTE":"Q","ORDER":"S","DISPATCH":"IR","INVOICE":"F"}.get(doc_type,"D")
    year=datetime.utcnow().strftime("%y")
    last=db.execute(select(Document).where(Document.doc_type==doc_type).order_by(desc(Document.id)).limit(1)).scalar_one_or_none()
    n=0
    if last:
        try:n=int(last.number.split("-")[-1])
        except:n=last.id
    return f"{prefix}{year}-{n+1:06d}"

def totals(lines):
    st=sum(l['qty']*l['unit_price'] for l in lines)
    vt=sum(l['qty']*l['unit_price']*l.get('vat_rate',20)/100 for l in lines)
    return round(st,2), round(vt,2), round(st+vt,2)

# --- AUTH ---
class UserOut(BaseModel):
    id:int; username:str; full_name:Optional[str]=None; email:Optional[str]=None; roles:List[str]=[]
@app.post("/auth/register", response_model=UserOut)
def register(p:RegisterIn, db:Session=Depends(get_db)):
    if db.execute(select(User).where(User.username==p.username)).scalar_one_or_none(): raise HTTPException(400,"Username exists")
    u=User(username=p.username, full_name=p.full_name, email=p.email, hashed_password=hash_pw(p.password))
    # roles
    rs=[]
    for rn in (p.roles or []):
        r=db.execute(select(Role).where(Role.name==rn)).scalar_one_or_none()
        if not r: r=Role(name=rn); db.add(r); db.commit(); db.refresh(r)
        rs.append(r)
    u.roles=rs; db.add(u); db.commit(); db.refresh(u)
    return UserOut(id=u.id, username=u.username, full_name=u.full_name, email=u.email, roles=[r.name for r in u.roles])

@app.post("/auth/login", response_model=Token)
def login(p:LoginIn, db:Session=Depends(get_db)):
    u=db.execute(select(User).where(User.username==p.username)).scalar_one_or_none()
    if not u or not verify_pw(p.password, u.hashed_password): raise HTTPException(401,"Invalid credentials")
    return {"access_token": make_token(u.username), "token_type":"bearer"}

# --- Masters ---
@app.post("/warehouses/")
def create_wh(p:WarehouseIn, db:Session=Depends(get_db), user=Depends(require_roles("Admin"))):
    if db.execute(select(Warehouse).where(Warehouse.code==p.code)).scalar_one_or_none(): raise HTTPException(400,"exists")
    wh=Warehouse(code=p.code, name=p.name); db.add(wh); db.commit(); return {"id":wh.id}

@app.post("/items/")
def create_item(p:ItemIn, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Depo"))):
    if db.execute(select(Item).where(Item.code==p.code)).scalar_one_or_none(): raise HTTPException(400,"exists")
    it=Item(**p.model_dump()); db.add(it); db.commit(); return {"id":it.id}

@app.post("/parties/")
def create_party(p:PartyIn, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Muhasebe","Satis"))):
    if db.execute(select(Party).where(Party.code==p.code)).scalar_one_or_none(): raise HTTPException(400,"exists")
    pr=Party(**p.model_dump()); db.add(pr); db.commit(); return {"id":pr.id}

# --- Stock ---
@app.post("/stock/move")
def stock_move(p:StockMoveIn, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Depo"))):
    it=db.execute(select(Item).where(Item.code==p.item_code)).scalar_one_or_none()
    if not it: raise HTTPException(400,"item not found")
    wh_from=db.execute(select(Warehouse).where(Warehouse.code==p.wh_from_code)).scalar_one_or_none() if p.wh_from_code else None
    wh_to=db.execute(select(Warehouse).where(Warehouse.code==p.wh_to_code)).scalar_one_or_none() if p.wh_to_code else None
    if p.move_type=="IN":
        if not wh_to: raise HTTPException(400,"IN requires wh_to")
        st=db.query(Stock).filter_by(item_id=it.id, warehouse_id=wh_to.id).one_or_none()
        if not st: st=Stock(item_id=it.id, warehouse_id=wh_to.id, qty=0.0, avg_cost=0.0); db.add(st)
        total=st.avg_cost*st.qty + p.unit_price*p.qty
        st.qty += p.qty; st.avg_cost=(total/st.qty) if st.qty else 0.0
        db.add(StockMove(item_id=it.id, wh_to=wh_to.id, qty=p.qty, unit_price=p.unit_price, move_type="IN", ref=p.ref))
    elif p.move_type=="OUT":
        if not wh_from: raise HTTPException(400,"OUT requires wh_from")
        st=db.query(Stock).filter_by(item_id=it.id, warehouse_id=wh_from.id).one_or_none()
        if not st or st.qty < p.qty: raise HTTPException(400,"insufficient")
        st.qty -= p.qty
        db.add(StockMove(item_id=it.id, wh_from=wh_from.id, qty=p.qty, unit_price=p.unit_price, move_type="OUT", ref=p.ref))
    elif p.move_type=="TRANSFER":
        if not (wh_from and wh_to): raise HTTPException(400,"TRANSFER needs both warehouses")
        st=db.query(Stock).filter_by(item_id=it.id, warehouse_id=wh_from.id).one_or_none()
        if not st or st.qty < p.qty: raise HTTPException(400,"insufficient")
        st.qty -= p.qty; db.add(StockMove(item_id=it.id, wh_from=wh_from.id, qty=p.qty, unit_price=p.unit_price, move_type="OUT", ref=p.ref))
        st2=db.query(Stock).filter_by(item_id=it.id, warehouse_id=wh_to.id).one_or_none()
        if not st2: st2=Stock(item_id=it.id, warehouse_id=wh_to.id, qty=0.0, avg_cost=0.0); db.add(st2)
        st2.qty += p.qty; db.add(StockMove(item_id=it.id, wh_to=wh_to.id, qty=p.qty, unit_price=p.unit_price, move_type="IN", ref=p.ref))
    else: raise HTTPException(400,"invalid move_type")
    db.commit(); return {"ok":True}

@app.get("/stock/snapshot")
def snapshot(db:Session=Depends(get_db), user=Depends(require_roles("Admin","Depo","Muhasebe"))):
    out=[]
    for r in db.query(Stock).all():
        item=db.get(Item,r.item_id); wh=db.get(Warehouse,r.warehouse_id)
        out.append({"item_code":item.code,"warehouse_code":wh.code,"qty":r.qty,"avg_cost":r.avg_cost})
    return out

# --- Sales Docs ---
def convert(db:Session, src_id:int, dst_type:str)->Document:
    src=db.get(Document, src_id)
    if not src: raise HTTPException(404,"source not found")
    dst=Document(doc_type=dst_type, number=next_number(db, dst_type), party_id=src.party_id, currency=src.currency, notes=f"Converted from {src.doc_type} {src.number}")
    db.add(dst); db.commit(); db.refresh(dst)
    src_lines=db.execute(select(DocumentLine).where(DocumentLine.document_id==src.id)).scalars().all()
    lines=[]
    for sl in src_lines:
        db.add(DocumentLine(document_id=dst.id, item_id=sl.item_id, qty=sl.qty, unit_price=sl.unit_price, vat_rate=sl.vat_rate, line_total=sl.line_total))
        lines.append({"qty":sl.qty,"unit_price":sl.unit_price,"vat_rate":sl.vat_rate})
    st,vt,gt=totals(lines); dst.subtotal, dst.vat_total, dst.grand_total=st,vt,gt; db.commit(); return dst

class DocumentOut(BaseModel):
    id:int; doc_type:str; number:str; grand_total:float
@app.post("/docs/", response_model=DocumentOut)
def create_doc(p:DocumentIn, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Satis","Muhasebe"))):
    party=db.execute(select(Party).where(Party.code==p.party_code)).scalar_one_or_none()
    if not party: raise HTTPException(400,"party not found")
    number=p.number or next_number(db, p.doc_type)
    doc=Document(doc_type=p.doc_type, number=number, party_id=party.id, currency=p.currency, notes=p.notes)
    db.add(doc); db.commit(); db.refresh(doc)
    lines=[]
    for ln in p.lines:
        it=db.execute(select(Item).where(Item.code==ln.item_code)).scalar_one_or_none()
        if not it: it=Item(code=ln.item_code, name=ln.item_code, type="Mamul", unit="adet"); db.add(it); db.commit(); db.refresh(it)
        db.add(DocumentLine(document_id=doc.id, item_id=it.id, qty=ln.qty, unit_price=ln.unit_price, vat_rate=ln.vat_rate, line_total=ln.qty*ln.unit_price*(1+ln.vat_rate/100)))
        lines.append({"qty":ln.qty,"unit_price":ln.unit_price,"vat_rate":ln.vat_rate})
    st,vt,gt=totals(lines); doc.subtotal, doc.vat_total, doc.grand_total=st,vt,gt; db.commit()
    return DocumentOut(id=doc.id, doc_type=doc.doc_type, number=doc.number, grand_total=doc.grand_total)

@app.post("/docs/{doc_id}/to-order")
def to_order(doc_id:int, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Satis"))): return {"id": convert(db, doc_id, "ORDER").id}
@app.post("/docs/{doc_id}/to-dispatch")
def to_dispatch(doc_id:int, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Satis","Depo"))): return {"id": convert(db, doc_id, "DISPATCH").id}
@app.post("/docs/{doc_id}/to-invoice")
def to_invoice(doc_id:int, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Satis","Muhasebe"))): return {"id": convert(db, doc_id, "INVOICE").id}

# --- Finance ---
@app.post("/finance/accounts")
def create_account(p:CashBankCreate, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Muhasebe"))):
    if p.account_type=="CASH":
        if db.execute(select(CashAccount).where(CashAccount.name==p.name)).scalar_one_or_none(): raise HTTPException(400,"exists")
        acc=CashAccount(name=p.name); db.add(acc); db.commit(); return {"id":acc.id}
    elif p.account_type=="BANK":
        if db.execute(select(BankAccount).where(BankAccount.name==p.name)).scalar_one_or_none(): raise HTTPException(400,"exists")
        acc=BankAccount(name=p.name, iban=p.iban); db.add(acc); db.commit(); return {"id":acc.id}
    else: raise HTTPException(400,"invalid type")

@app.post("/finance/tx")
def create_tx(p:TxCreate, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Muhasebe"))):
    if p.account_type=="CASH":
        acc=db.execute(select(CashAccount).where(CashAccount.name==p.account_name)).scalar_one_or_none()
        if not acc: raise HTTPException(400,"cash not found")
        tx=CashBankTx(account_type="CASH", account_id=acc.id, direction=p.direction, amount=p.amount, currency=p.currency, ref=p.ref, notes=p.notes)
    elif p.account_type=="BANK":
        acc=db.execute(select(BankAccount).where(BankAccount.name==p.account_name)).scalar_one_or_none()
        if not acc: raise HTTPException(400,"bank not found")
        tx=CashBankTx(account_type="BANK", account_id=acc.id, direction=p.direction, amount=p.amount, currency=p.currency, ref=p.ref, notes=p.notes)
    else: raise HTTPException(400,"invalid type")
    db.add(tx); db.commit(); return {"id":tx.id}

@app.post("/finance/cheques")
def create_cheque(p:ChequeCreate, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Muhasebe"))):
    if db.execute(select(Cheque).where(Cheque.number==p.number)).scalar_one_or_none(): raise HTTPException(400,"exists")
    ch=Cheque(number=p.number, amount=p.amount, currency=p.currency, due_date=p.due_date, status=p.status, notes=p.notes)
    db.add(ch); db.commit(); return {"id":ch.id}

# --- Production ---
def next_wo(db:Session)->str:
    year=datetime.utcnow().strftime("%y")
    last=db.execute(select(WorkOrder).order_by(desc(WorkOrder.id)).limit(1)).scalar_one_or_none()
    n=(last.id if last else 0)+1
    return f"WO{year}-{n:06d}"

@app.post("/production/wo")
def create_wo(p:WOCreate, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Uretim"))):
    prod=db.execute(select(Item).where(Item.code==p.product_code)).scalar_one_or_none()
    if not prod: raise HTTPException(400,"product not found")
    wo=WorkOrder(number=next_wo(db), product_id=prod.id, target_qty=p.target_qty, notes=p.notes, status="IN_PROGRESS")
    db.add(wo); db.commit(); return {"id":wo.id,"number":wo.number}

@app.post("/production/consume")
def consume(p:WOConsumeIn, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Uretim","Depo"))):
    wo=db.get(WorkOrder, p.wo_id)
    if not wo or wo.status not in ("IN_PROGRESS","OPEN"): raise HTTPException(400,"wo closed/not found")
    it=db.execute(select(Item).where(Item.code==p.item_code)).scalar_one_or_none()
    if not it: raise HTTPException(400,"item not found")
    wh=db.execute(select(Warehouse).where(Warehouse.code==p.warehouse_code)).scalar_one_or_none()
    if not wh: raise HTTPException(400,"warehouse not found")
    st=db.query(Stock).filter_by(item_id=it.id, warehouse_id=wh.id).one_or_none()
    if not st or st.qty < p.qty: raise HTTPException(400,"insufficient")
    st.qty -= p.qty; db.add(WorkOrderConsumption(wo_id=wo.id, item_id=it.id, qty=p.qty, wh_id=wh.id, ref=p.ref)); db.commit(); return {"ok":True}

@app.post("/production/produce")
def produce(p:WOProduceIn, db:Session=Depends(get_db), user=Depends(require_roles("Admin","Uretim"))):
    wo=db.get(WorkOrder, p.wo_id)
    if not wo or wo.status not in ("IN_PROGRESS","OPEN"): raise HTTPException(400,"wo closed/not found")
    wh=db.execute(select(Warehouse).where(Warehouse.code==p.warehouse_code)).scalar_one_or_none()
    if not wh: raise HTTPException(400,"warehouse not found")
    cons=db.execute(select(WorkOrderConsumption).where(WorkOrderConsumption.wo_id==wo.id)).scalars().all()
    mat_cost=0.0
    for c in cons:
        any_stock=db.query(Stock).filter_by(item_id=c.item_id).first()
        avg=any_stock.avg_cost if any_stock else 0.0
        mat_cost += avg * c.qty
    unit_cost=((mat_cost*(1+p.overhead_rate))/p.qty) if p.qty else 0.0
    st_fg=db.query(Stock).filter_by(item_id=wo.product_id, warehouse_id=wh.id).one_or_none()
    if not st_fg: st_fg=Stock(item_id=wo.product_id, warehouse_id=wh.id, qty=0.0, avg_cost=0.0); db.add(st_fg)
    total_prev=st_fg.avg_cost*st_fg.qty
    st_fg.qty += p.qty
    st_fg.avg_cost=(total_prev + unit_cost*p.qty)/st_fg.qty if st_fg.qty else unit_cost
    db.add(WorkOrderFG(wo_id=wo.id, product_id=wo.product_id, qty=p.qty, wh_id=wh.id, unit_cost=unit_cost))
    wo.produced_qty += p.qty; db.commit(); return {"ok":True,"unit_cost":round(unit_cost,3)}
# ---- Basit web arayüz (gömülü) ----
MINI_UI = """<!doctype html><meta charset="utf-8"><title>Fixar Mini UI</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<body style="font:14px system-ui;margin:20px;max-width:680px">
<h2>Fixar ERP – Mini</h2>
<label>Backend URL</label>
<input id="base" value="" style="width:100%"><br><br>
<label>Kullanıcı / Şifre</label>
<input id="u" placeholder="admin"> <input id="p" placeholder="123456" type="password">
<button onclick="login()">Giriş</button>
<pre id="out" style="background:#f4f4f4;padding:12px;white-space:pre-wrap"></pre>
<hr>
<button onclick="health()">/health kontrol</button>
<button onclick="seed()">Örnek verileri yükle</button>
<button onclick="snapshot()">Stok snapshot</button>
<table id="tbl" border="1" cellpadding="6" style="width:100%;margin-top:10px;display:none">
<thead><tr><th>Stok</th><th>Depo</th><th>Miktar</th><th>Ortalama Maliyet</th></tr></thead><tbody></tbody></table>
<script>
let token="";
const B=()=>document.getElementById('base').value.replace(/\/+$/,'');
const out=(x)=>document.getElementById('out').textContent=typeof x==="string"?x:JSON.stringify(x,null,2);
async function api(p,m="GET",b){let r=await fetch(B()+p,{method:m,headers:Object.assign({"Content-Type":"application/json"},token?{"Authorization":"Bearer "+token}:{}) ,body:b?JSON.stringify(b):null});let d=await r.json().catch(()=>({status:r.status}));if(!r.ok)throw d;return d;}
async function login(){try{document.getElementById('base').value ||= location.origin; let d=await api("/auth/login","POST",{username:document.getElementById('u').value||"admin",password:document.getElementById('p').value||"123456"});token=d.access_token;out("Giriş OK");}catch(e){out(e)}}
async function health(){try{document.getElementById('base').value ||= location.origin; out(await api("/health"));}catch(e){out(e)}}
async function seed(){try{
  document.getElementById('base').value ||= location.origin;
  try{await api("/auth/register","POST",{username:"admin",password:"123456",roles:["Admin","Depo","Satis","Muhasebe","Uretim"]})}catch(_){}
  if(!token){let d=await api("/auth/login","POST",{username:"admin",password:"123456"});token=d.access_token;}
  try{await api("/warehouses/","POST",{code:"MERKEZ-HAMMADDE",name:"Merkez Hammadde"})}catch(_){}
  try{await api("/warehouses/","POST",{code:"MERKEZ-MAMUL",name:"Merkez Mamul"})}catch(_){}
  try{await api("/items/","POST",{code:"10100-POLIOL",name:"Poliol 10100",type:"Hammadde",unit:"kg",vat_rate:20})}catch(_){}
  try{await api("/items/","POST",{code:"FIXAR-USPA-MEM-PRINT",name:"USPA Mem Print",type:"Mamul",unit:"adet",vat_rate:20})}catch(_){}
  try{await api("/parties/","POST",{code:"USPA",name:"USPA",type:"Musteri",vade_gun:180})}catch(_){}
  try{await api("/stock/move","POST",{item_code:"10100-POLIOL",wh_to_code:"MERKEZ-HAMMADDE",qty:100,unit_price:97,move_type:"IN",ref:"ALIS-001"})}catch(_){}
  out("Örnek veriler yüklendi");
}catch(e){out(e)}}
async function snapshot(){try{document.getElementById('base').value ||= location.origin; let d=await api("/stock/snapshot");let tb=document.querySelector("#tbl");let tbdy=tb.querySelector("tbody");tbdy.innerHTML=d.map(r=>`<tr><td>${r.item_code}</td><td>${r.warehouse_code}</td><td>${r.qty}</td><td>${r.avg_cost}</td></tr>`).join("");tb.style.display="table";out("Snapshot OK")}catch(e){out(e)}}
</script>"""

@app.get("/", response_class=HTMLResponse)
def root_page():
    # Ana sayfa: /ui ve /docs linkleri
    return HTMLResponse(
        '<meta charset="utf-8"><body style="font:14px system-ui;padding:20px">'
        '<h2>Fixar ERP API</h2>'
        '<p>Uygulama ayakta. Seçenekler:</p>'
        '<p>• <a href="/ui">Mini Arayüz</a><br>• <a href="/docs">API Dokümanı</a></p>'
        '</body>'
    )

@app.get("/ui", response_class=HTMLResponse)
def mini_ui():
    return HTMLResponse(MINI_UI)
