.class public final Lk70/t0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lk70/a1;

.field public final b:Lk70/v;


# direct methods
.method public constructor <init>(Lk70/a1;Lk70/v;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk70/t0;->a:Lk70/a1;

    .line 5
    .line 6
    iput-object p2, p0, Lk70/t0;->b:Lk70/v;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lk70/s0;

    .line 5
    .line 6
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    iget-object v1, p0, Lk70/t0;->b:Lk70/v;

    .line 10
    .line 11
    check-cast v1, Li70/b;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    iput-boolean v2, v1, Li70/b;->c:Z

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    iput-object v2, v1, Li70/b;->e:Ll70/a0;

    .line 18
    .line 19
    iput-object v2, v1, Li70/b;->b:Ll70/h;

    .line 20
    .line 21
    iput-object v2, v1, Li70/b;->d:Ljava/lang/Integer;

    .line 22
    .line 23
    iget-object p0, p0, Lk70/t0;->a:Lk70/a1;

    .line 24
    .line 25
    check-cast p0, Liy/b;

    .line 26
    .line 27
    sget-object v1, Lly/b;->S3:Lly/b;

    .line 28
    .line 29
    invoke-interface {p0, v1}, Ltl0/a;->a(Lul0/f;)V

    .line 30
    .line 31
    .line 32
    return-object v0
.end method
