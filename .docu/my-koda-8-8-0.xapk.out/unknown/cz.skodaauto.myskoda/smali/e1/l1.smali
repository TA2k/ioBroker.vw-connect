.class public final synthetic Le1/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Le1/n1;


# direct methods
.method public synthetic constructor <init>(Le1/n1;I)V
    .locals 0

    .line 1
    iput p2, p0, Le1/l1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le1/l1;->e:Le1/n1;

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
    .locals 5

    .line 1
    iget v0, p0, Le1/l1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Le3/k0;

    .line 7
    .line 8
    const-string v0, "$this$graphicsLayer"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Le1/l1;->e:Le1/n1;

    .line 14
    .line 15
    iget-object p0, p0, Le1/n1;->a:Ll2/g1;

    .line 16
    .line 17
    invoke-virtual {p0}, Ll2/g1;->o()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    int-to-float p0, p0

    .line 22
    neg-float p0, p0

    .line 23
    const/high16 v0, 0x40000000    # 2.0f

    .line 24
    .line 25
    div-float/2addr p0, v0

    .line 26
    invoke-virtual {p1, p0}, Le3/k0;->D(F)V

    .line 27
    .line 28
    .line 29
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0

    .line 32
    :pswitch_0
    check-cast p1, Ljava/lang/Float;

    .line 33
    .line 34
    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    iget-object p0, p0, Le1/l1;->e:Le1/n1;

    .line 39
    .line 40
    iget-object v0, p0, Le1/n1;->a:Ll2/g1;

    .line 41
    .line 42
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    int-to-float v1, v1

    .line 47
    add-float/2addr v1, p1

    .line 48
    iget v2, p0, Le1/n1;->e:F

    .line 49
    .line 50
    add-float/2addr v1, v2

    .line 51
    iget-object v2, p0, Le1/n1;->d:Ll2/g1;

    .line 52
    .line 53
    invoke-virtual {v2}, Ll2/g1;->o()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    int-to-float v2, v2

    .line 58
    const/4 v3, 0x0

    .line 59
    invoke-static {v1, v3, v2}, Lkp/r9;->d(FFF)F

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    cmpg-float v1, v1, v2

    .line 64
    .line 65
    if-nez v1, :cond_0

    .line 66
    .line 67
    const/4 v1, 0x1

    .line 68
    goto :goto_0

    .line 69
    :cond_0
    const/4 v1, 0x0

    .line 70
    :goto_0
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    int-to-float v3, v3

    .line 75
    sub-float/2addr v2, v3

    .line 76
    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    .line 77
    .line 78
    .line 79
    move-result v3

    .line 80
    invoke-virtual {v0}, Ll2/g1;->o()I

    .line 81
    .line 82
    .line 83
    move-result v4

    .line 84
    add-int/2addr v4, v3

    .line 85
    invoke-virtual {v0, v4}, Ll2/g1;->p(I)V

    .line 86
    .line 87
    .line 88
    int-to-float v0, v3

    .line 89
    sub-float v0, v2, v0

    .line 90
    .line 91
    iput v0, p0, Le1/n1;->e:F

    .line 92
    .line 93
    if-nez v1, :cond_1

    .line 94
    .line 95
    move p1, v2

    .line 96
    :cond_1
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    return-object p0

    .line 101
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
