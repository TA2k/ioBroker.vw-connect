.class public final Lx4/l;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Lx4/l;

.field public static final h:Lx4/l;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lx4/l;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lx4/l;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lx4/l;->g:Lx4/l;

    .line 9
    .line 10
    new-instance v0, Lx4/l;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lx4/l;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lx4/l;->h:Lx4/l;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lx4/l;->f:I

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
    .locals 2

    .line 1
    iget p0, p0, Lx4/l;->f:I

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
    and-int/lit8 p2, p0, 0x3

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    const/4 v1, 0x1

    .line 18
    if-eq p2, v0, :cond_0

    .line 19
    .line 20
    move p2, v1

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p2, 0x0

    .line 23
    :goto_0
    and-int/2addr p0, v1

    .line 24
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_1

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_1
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 34
    .line 35
    .line 36
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 40
    .line 41
    check-cast p2, Ljava/lang/Number;

    .line 42
    .line 43
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    and-int/lit8 p2, p0, 0x3

    .line 48
    .line 49
    const/4 v0, 0x2

    .line 50
    const/4 v1, 0x1

    .line 51
    if-eq p2, v0, :cond_2

    .line 52
    .line 53
    move p2, v1

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    const/4 p2, 0x0

    .line 56
    :goto_2
    and-int/2addr p0, v1

    .line 57
    check-cast p1, Ll2/t;

    .line 58
    .line 59
    invoke-virtual {p1, p0, p2}, Ll2/t;->O(IZ)Z

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    if-eqz p0, :cond_3

    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 67
    .line 68
    .line 69
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 70
    .line 71
    return-object p0

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
