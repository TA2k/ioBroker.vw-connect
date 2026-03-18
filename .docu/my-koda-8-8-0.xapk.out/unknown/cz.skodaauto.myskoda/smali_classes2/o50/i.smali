.class public final Lo50/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Lo50/i;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lo50/i;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lo50/i;->d:Lo50/i;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    check-cast p1, Lz4/e;

    .line 2
    .line 3
    const-string p0, "$this$constrainAs"

    .line 4
    .line 5
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p1, Lz4/e;->c:Lz4/f;

    .line 9
    .line 10
    invoke-static {p1, p0}, Lz4/e;->b(Lz4/e;Lz4/f;)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p1, Lz4/e;->f:Ly7/k;

    .line 14
    .line 15
    iget-object p0, p0, Lz4/f;->f:Lz4/h;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    const/4 v1, 0x6

    .line 19
    invoke-static {p1, p0, v0, v1}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 20
    .line 21
    .line 22
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0
.end method
