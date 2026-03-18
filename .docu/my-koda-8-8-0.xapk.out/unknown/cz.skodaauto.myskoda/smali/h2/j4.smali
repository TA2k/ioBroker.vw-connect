.class public final synthetic Lh2/j4;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ll2/t2;


# direct methods
.method public synthetic constructor <init>(Ll2/t2;I)V
    .locals 0

    .line 1
    iput p2, p0, Lh2/j4;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/j4;->e:Ll2/t2;

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
    .locals 12

    .line 1
    iget v0, p0, Lh2/j4;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Le3/k0;

    .line 7
    .line 8
    iget-object p0, p0, Lh2/j4;->e:Ll2/t2;

    .line 9
    .line 10
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ljava/lang/Number;

    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-virtual {p1, p0}, Le3/k0;->b(F)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    return-object p0

    .line 26
    :pswitch_0
    check-cast p1, Lt4/c;

    .line 27
    .line 28
    iget-object p0, p0, Lh2/j4;->e:Ll2/t2;

    .line 29
    .line 30
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lt4/f;

    .line 35
    .line 36
    iget p0, p0, Lt4/f;->d:F

    .line 37
    .line 38
    invoke-interface {p1, p0}, Lt4/c;->Q(F)I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    int-to-long p0, p0

    .line 43
    const/16 v0, 0x20

    .line 44
    .line 45
    shl-long/2addr p0, v0

    .line 46
    const/4 v0, 0x0

    .line 47
    int-to-long v0, v0

    .line 48
    const-wide v2, 0xffffffffL

    .line 49
    .line 50
    .line 51
    .line 52
    .line 53
    and-long/2addr v0, v2

    .line 54
    or-long/2addr p0, v0

    .line 55
    new-instance v0, Lt4/j;

    .line 56
    .line 57
    invoke-direct {v0, p0, p1}, Lt4/j;-><init>(J)V

    .line 58
    .line 59
    .line 60
    return-object v0

    .line 61
    :pswitch_1
    move-object v1, p1

    .line 62
    check-cast v1, Lg3/d;

    .line 63
    .line 64
    iget-object p0, p0, Lh2/j4;->e:Ll2/t2;

    .line 65
    .line 66
    invoke-interface {p0}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    check-cast p0, Le3/s;

    .line 71
    .line 72
    iget-wide v2, p0, Le3/s;->a:J

    .line 73
    .line 74
    sget-wide p0, Le3/s;->i:J

    .line 75
    .line 76
    invoke-static {v2, v3, p0, p1}, Le3/s;->c(JJ)Z

    .line 77
    .line 78
    .line 79
    move-result p0

    .line 80
    if-nez p0, :cond_0

    .line 81
    .line 82
    const/4 v10, 0x0

    .line 83
    const/16 v11, 0x7e

    .line 84
    .line 85
    const-wide/16 v4, 0x0

    .line 86
    .line 87
    const-wide/16 v6, 0x0

    .line 88
    .line 89
    const/4 v8, 0x0

    .line 90
    const/4 v9, 0x0

    .line 91
    invoke-static/range {v1 .. v11}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 92
    .line 93
    .line 94
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 95
    .line 96
    return-object p0

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
