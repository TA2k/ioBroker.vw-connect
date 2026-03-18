.class public final Luz/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final e:Luz/r;

.field public static final f:Luz/r;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Luz/r;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Luz/r;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Luz/r;->e:Luz/r;

    .line 8
    .line 9
    new-instance v0, Luz/r;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Luz/r;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Luz/r;->f:Luz/r;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Luz/r;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Luz/r;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lz4/e;

    .line 7
    .line 8
    const-string p0, "$this$constrainAs"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 14
    .line 15
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 16
    .line 17
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    const/4 v3, 0x6

    .line 21
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 22
    .line 23
    .line 24
    iget-object p0, p1, Lz4/e;->f:Ly7/k;

    .line 25
    .line 26
    iget-object v1, v0, Lz4/f;->f:Lz4/h;

    .line 27
    .line 28
    invoke-static {p0, v1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 29
    .line 30
    .line 31
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 32
    .line 33
    iget-object p1, v0, Lz4/f;->d:Lz4/h;

    .line 34
    .line 35
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 36
    .line 37
    .line 38
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 42
    .line 43
    const-string p0, "$this$constrainAs"

    .line 44
    .line 45
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 49
    .line 50
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 51
    .line 52
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    const/4 v3, 0x6

    .line 56
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 57
    .line 58
    .line 59
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 60
    .line 61
    iget-object p1, v0, Lz4/f;->d:Lz4/h;

    .line 62
    .line 63
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 64
    .line 65
    .line 66
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
