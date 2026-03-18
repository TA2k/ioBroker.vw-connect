.class public final Lwv/e;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Lwv/e;

.field public static final h:Lwv/e;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lwv/e;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lwv/e;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lwv/e;->g:Lwv/e;

    .line 9
    .line 10
    new-instance v0, Lwv/e;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lwv/e;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lwv/e;->h:Lwv/e;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lwv/e;->f:I

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
    iget p0, p0, Lwv/e;->f:I

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
    check-cast p1, Ll2/t;

    .line 14
    .line 15
    const p0, 0x2753ab9c

    .line 16
    .line 17
    .line 18
    invoke-virtual {p1, p0}, Ll2/t;->Z(I)V

    .line 19
    .line 20
    .line 21
    sget-object p0, Lh2/p1;->a:Ll2/e0;

    .line 22
    .line 23
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Le3/s;

    .line 28
    .line 29
    iget-wide v0, p0, Le3/s;->a:J

    .line 30
    .line 31
    const/4 p0, 0x0

    .line 32
    invoke-virtual {p1, p0}, Ll2/t;->q(Z)V

    .line 33
    .line 34
    .line 35
    new-instance p0, Le3/s;

    .line 36
    .line 37
    invoke-direct {p0, v0, v1}, Le3/s;-><init>(J)V

    .line 38
    .line 39
    .line 40
    return-object p0

    .line 41
    :pswitch_0
    check-cast p1, Ll2/o;

    .line 42
    .line 43
    check-cast p2, Ljava/lang/Number;

    .line 44
    .line 45
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 46
    .line 47
    .line 48
    check-cast p1, Ll2/t;

    .line 49
    .line 50
    const p0, -0x73582045

    .line 51
    .line 52
    .line 53
    invoke-virtual {p1, p0}, Ll2/t;->Z(I)V

    .line 54
    .line 55
    .line 56
    sget-object p0, Lh2/rb;->a:Ll2/e0;

    .line 57
    .line 58
    invoke-virtual {p1, p0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    check-cast p0, Lg4/p0;

    .line 63
    .line 64
    const/4 p2, 0x0

    .line 65
    invoke-virtual {p1, p2}, Ll2/t;->q(Z)V

    .line 66
    .line 67
    .line 68
    return-object p0

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
