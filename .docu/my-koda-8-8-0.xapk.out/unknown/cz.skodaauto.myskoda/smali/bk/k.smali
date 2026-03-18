.class public final synthetic Lbk/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/g1;


# direct methods
.method public synthetic constructor <init>(Ll2/g1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lbk/k;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbk/k;->e:Ll2/g1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lbk/k;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lg4/l0;

    .line 7
    .line 8
    const-string v0, "textLayoutResult"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p1, p1, Lg4/l0;->b:Lg4/o;

    .line 14
    .line 15
    iget p1, p1, Lg4/o;->f:I

    .line 16
    .line 17
    iget-object p0, p0, Lbk/k;->e:Ll2/g1;

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 20
    .line 21
    .line 22
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 23
    .line 24
    return-object p0

    .line 25
    :pswitch_0
    check-cast p1, Lt3/y;

    .line 26
    .line 27
    const-string v0, "it"

    .line 28
    .line 29
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-interface {p1}, Lt3/y;->h()J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    const-wide v2, 0xffffffffL

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    and-long/2addr v0, v2

    .line 42
    long-to-int p1, v0

    .line 43
    iget-object p0, p0, Lbk/k;->e:Ll2/g1;

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :pswitch_1
    check-cast p1, Lt4/l;

    .line 50
    .line 51
    iget-wide v0, p1, Lt4/l;->a:J

    .line 52
    .line 53
    const-wide v2, 0xffffffffL

    .line 54
    .line 55
    .line 56
    .line 57
    .line 58
    and-long/2addr v0, v2

    .line 59
    long-to-int p1, v0

    .line 60
    iget-object p0, p0, Lbk/k;->e:Ll2/g1;

    .line 61
    .line 62
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :pswitch_2
    check-cast p1, Ljava/lang/Integer;

    .line 67
    .line 68
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    iget-object p0, p0, Lbk/k;->e:Ll2/g1;

    .line 73
    .line 74
    invoke-virtual {p0, p1}, Ll2/g1;->p(I)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
