.class public final Lkn/u;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# static fields
.field public static final g:Lkn/u;

.field public static final h:Lkn/u;

.field public static final i:Lkn/u;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lkn/u;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lkn/u;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lkn/u;->g:Lkn/u;

    .line 9
    .line 10
    new-instance v0, Lkn/u;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lkn/u;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lkn/u;->h:Lkn/u;

    .line 17
    .line 18
    new-instance v0, Lkn/u;

    .line 19
    .line 20
    const/4 v2, 0x2

    .line 21
    invoke-direct {v0, v1, v2}, Lkn/u;-><init>(II)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Lkn/u;->i:Lkn/u;

    .line 25
    .line 26
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lkn/u;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget p0, p0, Lkn/u;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p0, "it"

    .line 7
    .line 8
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    instance-of p0, p1, Lkn/f0;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    check-cast p1, Lkn/f0;

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move-object p1, v0

    .line 20
    :goto_0
    if-eqz p1, :cond_1

    .line 21
    .line 22
    new-instance p0, Lkn/c0;

    .line 23
    .line 24
    const/4 v0, 0x2

    .line 25
    invoke-direct {p0, p1, v0}, Lkn/c0;-><init>(Lkn/f0;I)V

    .line 26
    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    new-instance p0, Lkn/c0;

    .line 30
    .line 31
    const/4 p1, 0x3

    .line 32
    invoke-direct {p0, v0, p1}, Lkn/c0;-><init>(Lkn/f0;I)V

    .line 33
    .line 34
    .line 35
    :goto_1
    return-object p0

    .line 36
    :pswitch_0
    check-cast p1, Lkn/f0;

    .line 37
    .line 38
    const-string p0, "it"

    .line 39
    .line 40
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 44
    .line 45
    return-object p0

    .line 46
    :pswitch_1
    check-cast p1, Lkn/f0;

    .line 47
    .line 48
    const-string p0, "it"

    .line 49
    .line 50
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 54
    .line 55
    return-object p0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
