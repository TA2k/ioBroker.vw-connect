.class public final Lkn/l;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lkn/c0;


# direct methods
.method public synthetic constructor <init>(Lkn/c0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lkn/l;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lkn/l;->g:Lkn/c0;

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lkn/l;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lc1/c;

    .line 7
    .line 8
    const-string v0, "$this$animateTo"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Lc1/c;->d()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Ljava/lang/Number;

    .line 18
    .line 19
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    const/4 v0, 0x0

    .line 24
    const/high16 v1, 0x3f800000    # 1.0f

    .line 25
    .line 26
    invoke-static {p1, v0, v1}, Lkp/r9;->d(FFF)F

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    iget-object p0, p0, Lkn/l;->g:Lkn/c0;

    .line 31
    .line 32
    iget-object p0, p0, Lkn/c0;->e:Ll2/f1;

    .line 33
    .line 34
    invoke-virtual {p0, p1}, Ll2/f1;->p(F)V

    .line 35
    .line 36
    .line 37
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 38
    .line 39
    return-object p0

    .line 40
    :pswitch_0
    check-cast p1, Ld3/b;

    .line 41
    .line 42
    iget-wide v0, p1, Ld3/b;->a:J

    .line 43
    .line 44
    invoke-static {v0, v1}, Ld3/b;->f(J)F

    .line 45
    .line 46
    .line 47
    move-result p1

    .line 48
    iget-object p0, p0, Lkn/l;->g:Lkn/c0;

    .line 49
    .line 50
    iget-object v0, p0, Lkn/c0;->q:Lh6/j;

    .line 51
    .line 52
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 53
    .line 54
    .line 55
    move-result-wide v1

    .line 56
    const/4 v3, 0x0

    .line 57
    invoke-static {v3, p1}, Ljp/bf;->a(FF)J

    .line 58
    .line 59
    .line 60
    move-result-wide v3

    .line 61
    invoke-virtual {v0, v1, v2, v3, v4}, Lh6/j;->d(JJ)V

    .line 62
    .line 63
    .line 64
    iget-object p1, p0, Lkn/c0;->q:Lh6/j;

    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    const v0, 0x7f7fffff    # Float.MAX_VALUE

    .line 70
    .line 71
    .line 72
    invoke-static {v0, v0}, Lkp/g9;->a(FF)J

    .line 73
    .line 74
    .line 75
    move-result-wide v0

    .line 76
    invoke-virtual {p1, v0, v1}, Lh6/j;->e(J)J

    .line 77
    .line 78
    .line 79
    move-result-wide v0

    .line 80
    invoke-static {v0, v1}, Lt4/q;->c(J)F

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    iput p1, p0, Lkn/c0;->p:F

    .line 85
    .line 86
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 87
    .line 88
    return-object p0

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
