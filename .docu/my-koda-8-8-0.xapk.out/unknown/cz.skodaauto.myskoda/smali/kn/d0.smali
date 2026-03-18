.class public final Lkn/d0;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Lkn/d0;

.field public static final h:Lkn/d0;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lkn/d0;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lkn/d0;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lkn/d0;->g:Lkn/d0;

    .line 9
    .line 10
    new-instance v0, Lkn/d0;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lkn/d0;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lkn/d0;->h:Lkn/d0;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lkn/d0;->f:I

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
    iget p0, p0, Lkn/d0;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/o;

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
    and-int/lit8 p0, p0, 0xb

    .line 15
    .line 16
    const/4 p2, 0x2

    .line 17
    if-ne p0, p2, :cond_1

    .line 18
    .line 19
    check-cast p1, Ll2/t;

    .line 20
    .line 21
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-nez p0, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 29
    .line 30
    .line 31
    :cond_1
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    return-object p0

    .line 34
    :pswitch_0
    check-cast p1, Lu2/b;

    .line 35
    .line 36
    check-cast p2, Lkn/c0;

    .line 37
    .line 38
    const-string p0, "$this$Saver"

    .line 39
    .line 40
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const-string p0, "it"

    .line 44
    .line 45
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {p2}, Lkn/c0;->i()Lkn/f0;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-eqz p0, :cond_4

    .line 57
    .line 58
    const/4 p1, 0x1

    .line 59
    if-eq p0, p1, :cond_3

    .line 60
    .line 61
    const/4 p1, 0x2

    .line 62
    if-ne p0, p1, :cond_2

    .line 63
    .line 64
    sget-object p0, Lkn/f0;->f:Lkn/f0;

    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_2
    new-instance p0, La8/r0;

    .line 68
    .line 69
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_3
    sget-object p0, Lkn/f0;->e:Lkn/f0;

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_4
    sget-object p0, Lkn/f0;->d:Lkn/f0;

    .line 77
    .line 78
    :goto_1
    return-object p0

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
