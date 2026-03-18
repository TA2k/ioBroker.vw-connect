.class public final synthetic Li91/c0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;


# direct methods
.method public synthetic constructor <init>(ILay0/n;)V
    .locals 0

    .line 1
    iput p1, p0, Li91/c0;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Li91/c0;->e:Lay0/n;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Li91/c0;->d:I

    .line 2
    .line 3
    check-cast p1, Lk1/t;

    .line 4
    .line 5
    check-cast p2, Ll2/o;

    .line 6
    .line 7
    check-cast p3, Ljava/lang/Integer;

    .line 8
    .line 9
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 10
    .line 11
    .line 12
    move-result p3

    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    const-string v0, "$this$Card"

    .line 17
    .line 18
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    and-int/lit8 p1, p3, 0x11

    .line 22
    .line 23
    const/16 v0, 0x10

    .line 24
    .line 25
    const/4 v1, 0x0

    .line 26
    const/4 v2, 0x1

    .line 27
    if-eq p1, v0, :cond_0

    .line 28
    .line 29
    move p1, v2

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    move p1, v1

    .line 32
    :goto_0
    and-int/2addr p3, v2

    .line 33
    check-cast p2, Ll2/t;

    .line 34
    .line 35
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    if-eqz p1, :cond_1

    .line 40
    .line 41
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    iget-object p0, p0, Li91/c0;->e:Lay0/n;

    .line 46
    .line 47
    invoke-interface {p0, p2, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 52
    .line 53
    .line 54
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 55
    .line 56
    return-object p0

    .line 57
    :pswitch_0
    const-string v0, "$this$Card"

    .line 58
    .line 59
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    and-int/lit8 p1, p3, 0x11

    .line 63
    .line 64
    const/16 v0, 0x10

    .line 65
    .line 66
    const/4 v1, 0x0

    .line 67
    const/4 v2, 0x1

    .line 68
    if-eq p1, v0, :cond_2

    .line 69
    .line 70
    move p1, v2

    .line 71
    goto :goto_2

    .line 72
    :cond_2
    move p1, v1

    .line 73
    :goto_2
    and-int/2addr p3, v2

    .line 74
    check-cast p2, Ll2/t;

    .line 75
    .line 76
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    if-eqz p1, :cond_3

    .line 81
    .line 82
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    iget-object p0, p0, Li91/c0;->e:Lay0/n;

    .line 87
    .line 88
    invoke-interface {p0, p2, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 93
    .line 94
    .line 95
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 96
    .line 97
    return-object p0

    .line 98
    nop

    .line 99
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
