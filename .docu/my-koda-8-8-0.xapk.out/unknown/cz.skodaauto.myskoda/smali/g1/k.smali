.class public final Lg1/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lg1/e2;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Ljava/lang/Object;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput p1, p0, Lg1/k;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lg1/k;->b:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lg1/k;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(F)F
    .locals 4

    .line 1
    iget v0, p0, Lg1/k;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lg1/k;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lg1/u2;

    .line 9
    .line 10
    iget-object v1, v0, Lg1/u2;->h:Ld2/g;

    .line 11
    .line 12
    invoke-virtual {v1}, Ld2/g;->invoke()Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    check-cast v1, Ljava/lang/Boolean;

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    const/4 v3, 0x0

    .line 27
    cmpg-float v2, v2, v3

    .line 28
    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    if-eqz v1, :cond_1

    .line 33
    .line 34
    :goto_0
    iget-object p0, p0, Lg1/k;->c:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Lg1/t2;

    .line 37
    .line 38
    invoke-virtual {v0, p1}, Lg1/u2;->h(F)J

    .line 39
    .line 40
    .line 41
    move-result-wide v1

    .line 42
    invoke-virtual {v0, v1, v2}, Lg1/u2;->e(J)J

    .line 43
    .line 44
    .line 45
    move-result-wide v1

    .line 46
    const/4 p1, 0x2

    .line 47
    invoke-virtual {p0, p1, v1, v2}, Lg1/t2;->a(IJ)J

    .line 48
    .line 49
    .line 50
    move-result-wide p0

    .line 51
    invoke-virtual {v0, p0, p1}, Lg1/u2;->g(J)F

    .line 52
    .line 53
    .line 54
    move-result p0

    .line 55
    invoke-virtual {v0, p0}, Lg1/u2;->d(F)F

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    return p0

    .line 60
    :cond_1
    new-instance p0, Le1/x0;

    .line 61
    .line 62
    const-string p1, "The fling animation was cancelled"

    .line 63
    .line 64
    const/4 v0, 0x0

    .line 65
    invoke-direct {p0, p1, v0}, Lj1/c;-><init>(Ljava/lang/String;I)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :pswitch_0
    iget-object v0, p0, Lg1/k;->b:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v0, Lg1/m;

    .line 72
    .line 73
    iget-object v1, v0, Lg1/m;->C:Lg1/q;

    .line 74
    .line 75
    invoke-virtual {v1, p1}, Lg1/q;->j(F)F

    .line 76
    .line 77
    .line 78
    move-result p1

    .line 79
    iget-object v0, v0, Lg1/m;->C:Lg1/q;

    .line 80
    .line 81
    iget-object v0, v0, Lg1/q;->i:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v0, Ll2/f1;

    .line 84
    .line 85
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    sub-float v0, p1, v0

    .line 90
    .line 91
    iget-object p0, p0, Lg1/k;->c:Ljava/lang/Object;

    .line 92
    .line 93
    check-cast p0, Lg1/p;

    .line 94
    .line 95
    invoke-static {p0, p1}, Lg1/p;->b(Lg1/p;F)V

    .line 96
    .line 97
    .line 98
    return v0

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
