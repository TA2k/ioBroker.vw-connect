.class public final Lvv/s;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# static fields
.field public static final g:Lvv/s;

.field public static final h:Lvv/s;

.field public static final i:Lvv/s;

.field public static final j:Lvv/s;

.field public static final k:Lvv/s;

.field public static final l:Lvv/s;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lvv/s;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lvv/s;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lvv/s;->g:Lvv/s;

    .line 9
    .line 10
    new-instance v0, Lvv/s;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lvv/s;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lvv/s;->h:Lvv/s;

    .line 17
    .line 18
    new-instance v0, Lvv/s;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, v1, v2}, Lvv/s;-><init>(II)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lvv/s;->i:Lvv/s;

    .line 25
    .line 26
    new-instance v0, Lvv/s;

    .line 27
    .line 28
    const/4 v2, 0x3

    .line 29
    invoke-direct {v0, v1, v2}, Lvv/s;-><init>(II)V

    .line 30
    .line 31
    .line 32
    sput-object v0, Lvv/s;->j:Lvv/s;

    .line 33
    .line 34
    new-instance v0, Lvv/s;

    .line 35
    .line 36
    const/4 v2, 0x4

    .line 37
    invoke-direct {v0, v1, v2}, Lvv/s;-><init>(II)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lvv/s;->k:Lvv/s;

    .line 41
    .line 42
    new-instance v0, Lvv/s;

    .line 43
    .line 44
    const/4 v2, 0x5

    .line 45
    invoke-direct {v0, v1, v2}, Lvv/s;-><init>(II)V

    .line 46
    .line 47
    .line 48
    sput-object v0, Lvv/s;->l:Lvv/s;

    .line 49
    .line 50
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lvv/s;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget p0, p0, Lvv/s;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Lvv/p0;

    .line 7
    .line 8
    invoke-direct {p0}, Lvv/p0;-><init>()V

    .line 9
    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_0
    sget-object p0, Lvv/n0;->i:Lvv/n0;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_1
    sget-object p0, Lg4/p0;->d:Lg4/p0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_2
    sget-wide v0, Le3/s;->b:J

    .line 19
    .line 20
    new-instance p0, Le3/s;

    .line 21
    .line 22
    invoke-direct {p0, v0, v1}, Le3/s;-><init>(J)V

    .line 23
    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_3
    const/4 p0, 0x0

    .line 27
    return-object p0

    .line 28
    :pswitch_4
    const/4 p0, 0x0

    .line 29
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    return-object p0

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
