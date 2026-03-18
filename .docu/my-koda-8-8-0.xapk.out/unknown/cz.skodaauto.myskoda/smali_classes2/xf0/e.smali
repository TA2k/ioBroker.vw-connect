.class public final synthetic Lxf0/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/p;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/n;


# direct methods
.method public synthetic constructor <init>(ILay0/n;)V
    .locals 0

    .line 1
    iput p1, p0, Lxf0/e;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lxf0/e;->e:Lay0/n;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lxf0/e;->d:I

    .line 2
    .line 3
    check-cast p1, Lzl/s;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p2, Lzl/d;

    .line 9
    .line 10
    check-cast p3, Ll2/o;

    .line 11
    .line 12
    check-cast p4, Ljava/lang/Integer;

    .line 13
    .line 14
    invoke-virtual {p4}, Ljava/lang/Integer;->intValue()I

    .line 15
    .line 16
    .line 17
    move-result p4

    .line 18
    const-string v0, "<this>"

    .line 19
    .line 20
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    const-string p1, "it"

    .line 24
    .line 25
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    and-int/lit16 p1, p4, 0x81

    .line 29
    .line 30
    const/16 p2, 0x80

    .line 31
    .line 32
    const/4 v0, 0x0

    .line 33
    const/4 v1, 0x1

    .line 34
    if-eq p1, p2, :cond_0

    .line 35
    .line 36
    move p1, v1

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move p1, v0

    .line 39
    :goto_0
    and-int/lit8 p2, p4, 0x1

    .line 40
    .line 41
    check-cast p3, Ll2/t;

    .line 42
    .line 43
    invoke-virtual {p3, p2, p1}, Ll2/t;->O(IZ)Z

    .line 44
    .line 45
    .line 46
    move-result p1

    .line 47
    if-eqz p1, :cond_1

    .line 48
    .line 49
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    iget-object p0, p0, Lxf0/e;->e:Lay0/n;

    .line 54
    .line 55
    invoke-interface {p0, p3, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 60
    .line 61
    .line 62
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 63
    .line 64
    return-object p0

    .line 65
    :pswitch_0
    check-cast p2, Lzl/e;

    .line 66
    .line 67
    check-cast p3, Ll2/o;

    .line 68
    .line 69
    check-cast p4, Ljava/lang/Integer;

    .line 70
    .line 71
    invoke-virtual {p4}, Ljava/lang/Integer;->intValue()I

    .line 72
    .line 73
    .line 74
    move-result p4

    .line 75
    const-string v0, "<this>"

    .line 76
    .line 77
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    const-string p1, "it"

    .line 81
    .line 82
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    and-int/lit16 p1, p4, 0x81

    .line 86
    .line 87
    const/16 p2, 0x80

    .line 88
    .line 89
    const/4 v0, 0x0

    .line 90
    const/4 v1, 0x1

    .line 91
    if-eq p1, p2, :cond_2

    .line 92
    .line 93
    move p1, v1

    .line 94
    goto :goto_2

    .line 95
    :cond_2
    move p1, v0

    .line 96
    :goto_2
    and-int/lit8 p2, p4, 0x1

    .line 97
    .line 98
    check-cast p3, Ll2/t;

    .line 99
    .line 100
    invoke-virtual {p3, p2, p1}, Ll2/t;->O(IZ)Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    if-eqz p1, :cond_3

    .line 105
    .line 106
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 107
    .line 108
    .line 109
    move-result-object p1

    .line 110
    iget-object p0, p0, Lxf0/e;->e:Lay0/n;

    .line 111
    .line 112
    invoke-interface {p0, p3, p1}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_3
    invoke-virtual {p3}, Ll2/t;->R()V

    .line 117
    .line 118
    .line 119
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 120
    .line 121
    return-object p0

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
