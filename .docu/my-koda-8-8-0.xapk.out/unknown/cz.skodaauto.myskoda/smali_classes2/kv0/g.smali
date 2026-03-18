.class public final Lkv0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final e:Lkv0/g;

.field public static final f:Lkv0/g;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lkv0/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lkv0/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lkv0/g;->e:Lkv0/g;

    .line 8
    .line 9
    new-instance v0, Lkv0/g;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lkv0/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lkv0/g;->f:Lkv0/g;

    .line 16
    .line 17
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lkv0/g;->d:I

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
    iget p0, p0, Lkv0/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/String;

    .line 7
    .line 8
    const-string p0, "it"

    .line 9
    .line 10
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    check-cast p1, Lz4/e;

    .line 17
    .line 18
    const-string p0, "$this$constrainAs"

    .line 19
    .line 20
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object p0, p1, Lz4/e;->e:Ly41/a;

    .line 24
    .line 25
    iget-object v0, p1, Lz4/e;->c:Lz4/f;

    .line 26
    .line 27
    iget-object v1, v0, Lz4/f;->e:Lz4/g;

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    const/4 v3, 0x6

    .line 31
    invoke-static {p0, v1, v2, v3}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p1, Lz4/e;->d:Ly7/k;

    .line 35
    .line 36
    iget-object p1, v0, Lz4/f;->d:Lz4/h;

    .line 37
    .line 38
    invoke-static {p0, p1, v2, v3}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 39
    .line 40
    .line 41
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    return-object p0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
