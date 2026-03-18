.class public final Lj7/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Lj7/e;

.field public static final h:Lj7/e;

.field public static final i:Lj7/e;

.field public static final j:Lj7/e;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lj7/e;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lj7/e;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lj7/e;->g:Lj7/e;

    .line 9
    .line 10
    new-instance v0, Lj7/e;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lj7/e;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lj7/e;->h:Lj7/e;

    .line 17
    .line 18
    new-instance v0, Lj7/e;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, v1, v2}, Lj7/e;-><init>(II)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lj7/e;->i:Lj7/e;

    .line 25
    .line 26
    new-instance v0, Lj7/e;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-direct {v0, v1, v2}, Lj7/e;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Lj7/e;->j:Lj7/e;

    .line 33
    .line 34
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lj7/e;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lj7/e;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lj7/a;

    .line 7
    .line 8
    check-cast p2, Ljava/lang/Number;

    .line 9
    .line 10
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    iput p0, p1, Lj7/a;->c:I

    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    return-object p0

    .line 19
    :pswitch_0
    check-cast p1, Lj7/a;

    .line 20
    .line 21
    check-cast p2, Lj7/g;

    .line 22
    .line 23
    iput-object p2, p1, Lj7/a;->b:Lj7/g;

    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_1
    check-cast p1, Lj7/a;

    .line 29
    .line 30
    check-cast p2, Ly6/q;

    .line 31
    .line 32
    iput-object p2, p1, Lj7/a;->d:Ly6/q;

    .line 33
    .line 34
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 35
    .line 36
    return-object p0

    .line 37
    :pswitch_2
    check-cast p1, Lj7/a;

    .line 38
    .line 39
    check-cast p2, Ljava/lang/String;

    .line 40
    .line 41
    iput-object p2, p1, Lj7/a;->a:Ljava/lang/String;

    .line 42
    .line 43
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 44
    .line 45
    return-object p0

    .line 46
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
