.class public final Lmn/b;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# static fields
.field public static final g:Lmn/b;

.field public static final h:Lmn/b;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lmn/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lmn/b;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lmn/b;->g:Lmn/b;

    .line 9
    .line 10
    new-instance v0, Lmn/b;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lmn/b;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lmn/b;->h:Lmn/b;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lmn/b;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lmn/b;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lc1/r1;

    .line 7
    .line 8
    check-cast p2, Ll2/o;

    .line 9
    .line 10
    check-cast p3, Ljava/lang/Number;

    .line 11
    .line 12
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 13
    .line 14
    .line 15
    const-string p0, "$this$null"

    .line 16
    .line 17
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    check-cast p2, Ll2/t;

    .line 21
    .line 22
    const p0, -0x1a2bfc0e

    .line 23
    .line 24
    .line 25
    invoke-virtual {p2, p0}, Ll2/t;->Z(I)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    const/4 p1, 0x7

    .line 30
    const/4 p3, 0x0

    .line 31
    invoke-static {p3, p3, p0, p1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    const/4 p1, 0x0

    .line 36
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 37
    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    check-cast p1, Lc1/r1;

    .line 41
    .line 42
    check-cast p2, Ll2/o;

    .line 43
    .line 44
    check-cast p3, Ljava/lang/Number;

    .line 45
    .line 46
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 47
    .line 48
    .line 49
    const-string p0, "$this$null"

    .line 50
    .line 51
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    check-cast p2, Ll2/t;

    .line 55
    .line 56
    const p0, 0x5375fec

    .line 57
    .line 58
    .line 59
    invoke-virtual {p2, p0}, Ll2/t;->Z(I)V

    .line 60
    .line 61
    .line 62
    const/4 p0, 0x0

    .line 63
    const/4 p1, 0x7

    .line 64
    const/4 p3, 0x0

    .line 65
    invoke-static {p3, p3, p0, p1}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const/4 p1, 0x0

    .line 70
    invoke-virtual {p2, p1}, Ll2/t;->q(Z)V

    .line 71
    .line 72
    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
