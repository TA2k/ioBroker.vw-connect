.class public final Lco0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final d:Lco0/g;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lco0/g;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lco0/g;->d:Lco0/g;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

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
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 9
    .line 10
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 11
    .line 12
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 13
    .line 14
    const/4 v2, 0x0

    .line 15
    const/4 v3, 0x6

    .line 16
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 17
    .line 18
    .line 19
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 20
    .line 21
    iget-object p1, v0, Lz4/f;->f:Lz4/h;

    .line 22
    .line 23
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 24
    .line 25
    .line 26
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0
.end method
