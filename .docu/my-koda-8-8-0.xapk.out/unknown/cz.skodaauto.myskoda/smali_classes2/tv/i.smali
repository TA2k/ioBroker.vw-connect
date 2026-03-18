.class public final Ltv/i;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Ltv/i;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Ltv/i;->g:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x4

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Ltv/i;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Ljava/lang/Number;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    check-cast p2, Ljava/lang/Number;

    .line 13
    .line 14
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    check-cast p3, Ljava/lang/Number;

    .line 19
    .line 20
    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    check-cast p4, Ljava/lang/Number;

    .line 25
    .line 26
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 27
    .line 28
    .line 29
    move-result p2

    .line 30
    iget-object p0, p0, Ltv/i;->g:Ljava/lang/Object;

    .line 31
    .line 32
    move-object v0, p0

    .line 33
    check-cast v0, Landroid/view/ViewStructure;

    .line 34
    .line 35
    sub-int v5, p1, v1

    .line 36
    .line 37
    sub-int v6, p2, v2

    .line 38
    .line 39
    const/4 v3, 0x0

    .line 40
    const/4 v4, 0x0

    .line 41
    invoke-virtual/range {v0 .. v6}, Landroid/view/ViewStructure;->setDimens(IIIIII)V

    .line 42
    .line 43
    .line 44
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 45
    .line 46
    return-object p0

    .line 47
    :pswitch_0
    check-cast p1, Lt4/c;

    .line 48
    .line 49
    check-cast p2, Ljava/lang/String;

    .line 50
    .line 51
    check-cast p3, Ll2/o;

    .line 52
    .line 53
    check-cast p4, Ljava/lang/Number;

    .line 54
    .line 55
    invoke-virtual {p4}, Ljava/lang/Number;->intValue()I

    .line 56
    .line 57
    .line 58
    move-result p4

    .line 59
    const-string v0, "$this$$receiver"

    .line 60
    .line 61
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    const-string p1, "it"

    .line 65
    .line 66
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    and-int/lit16 p1, p4, 0x281

    .line 70
    .line 71
    const/16 p2, 0x80

    .line 72
    .line 73
    if-ne p1, p2, :cond_1

    .line 74
    .line 75
    move-object p1, p3

    .line 76
    check-cast p1, Ll2/t;

    .line 77
    .line 78
    invoke-virtual {p1}, Ll2/t;->A()Z

    .line 79
    .line 80
    .line 81
    move-result p2

    .line 82
    if-nez p2, :cond_0

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :cond_0
    invoke-virtual {p1}, Ll2/t;->R()V

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    :goto_0
    iget-object p0, p0, Ltv/i;->g:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast p0, Llp/la;

    .line 92
    .line 93
    check-cast p0, Luv/k;

    .line 94
    .line 95
    iget-object p1, p0, Luv/k;->b:Ljava/lang/String;

    .line 96
    .line 97
    iget-object p0, p0, Luv/k;->a:Ljava/lang/String;

    .line 98
    .line 99
    sget-object p2, Lx2/p;->b:Lx2/p;

    .line 100
    .line 101
    const/high16 p4, 0x3f800000    # 1.0f

    .line 102
    .line 103
    invoke-static {p2, p4}, Landroidx/compose/foundation/layout/d;->d(Lx2/s;F)Lx2/s;

    .line 104
    .line 105
    .line 106
    move-result-object p2

    .line 107
    const/16 p4, 0xd80

    .line 108
    .line 109
    invoke-static {p1, p0, p2, p3, p4}, Ltv/l;->a(Ljava/lang/String;Ljava/lang/String;Lx2/s;Ll2/o;I)V

    .line 110
    .line 111
    .line 112
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    return-object p0

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
