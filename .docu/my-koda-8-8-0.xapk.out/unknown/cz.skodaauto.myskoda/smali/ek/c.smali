.class public final synthetic Lek/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lac/a0;


# direct methods
.method public synthetic constructor <init>(Lac/a0;I)V
    .locals 0

    .line 1
    iput p2, p0, Lek/c;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lek/c;->e:Lac/a0;

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
    iget v0, p0, Lek/c;->d:I

    .line 2
    .line 3
    check-cast p1, Lk1/h1;

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
    const-string v0, "$this$DropdownMenuItem"

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
    iget-object p0, p0, Lek/c;->e:Lac/a0;

    .line 42
    .line 43
    iget-object p0, p0, Lac/a0;->d:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {p0, p2, v1}, Ldk/b;->c(Ljava/lang/String;Ll2/o;I)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 50
    .line 51
    .line 52
    :goto_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 53
    .line 54
    return-object p0

    .line 55
    :pswitch_0
    const-string v0, "$this$DropdownMenuItem"

    .line 56
    .line 57
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    and-int/lit8 p1, p3, 0x11

    .line 61
    .line 62
    const/16 v0, 0x10

    .line 63
    .line 64
    const/4 v1, 0x0

    .line 65
    const/4 v2, 0x1

    .line 66
    if-eq p1, v0, :cond_2

    .line 67
    .line 68
    move p1, v2

    .line 69
    goto :goto_2

    .line 70
    :cond_2
    move p1, v1

    .line 71
    :goto_2
    and-int/2addr p3, v2

    .line 72
    check-cast p2, Ll2/t;

    .line 73
    .line 74
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    if-eqz p1, :cond_3

    .line 79
    .line 80
    iget-object p0, p0, Lek/c;->e:Lac/a0;

    .line 81
    .line 82
    iget-object p0, p0, Lac/a0;->d:Ljava/lang/String;

    .line 83
    .line 84
    invoke-static {p0, p2, v1}, Ldk/b;->c(Ljava/lang/String;Ll2/o;I)V

    .line 85
    .line 86
    .line 87
    goto :goto_3

    .line 88
    :cond_3
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 89
    .line 90
    .line 91
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0

    .line 94
    :pswitch_1
    const-string v0, "$this$DropdownMenuItem"

    .line 95
    .line 96
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    and-int/lit8 p1, p3, 0x11

    .line 100
    .line 101
    const/16 v0, 0x10

    .line 102
    .line 103
    const/4 v1, 0x0

    .line 104
    const/4 v2, 0x1

    .line 105
    if-eq p1, v0, :cond_4

    .line 106
    .line 107
    move p1, v2

    .line 108
    goto :goto_4

    .line 109
    :cond_4
    move p1, v1

    .line 110
    :goto_4
    and-int/2addr p3, v2

    .line 111
    check-cast p2, Ll2/t;

    .line 112
    .line 113
    invoke-virtual {p2, p3, p1}, Ll2/t;->O(IZ)Z

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    if-eqz p1, :cond_5

    .line 118
    .line 119
    iget-object p0, p0, Lek/c;->e:Lac/a0;

    .line 120
    .line 121
    iget-object p0, p0, Lac/a0;->d:Ljava/lang/String;

    .line 122
    .line 123
    invoke-static {p0, p2, v1}, Ldk/b;->c(Ljava/lang/String;Ll2/o;I)V

    .line 124
    .line 125
    .line 126
    goto :goto_5

    .line 127
    :cond_5
    invoke-virtual {p2}, Ll2/t;->R()V

    .line 128
    .line 129
    .line 130
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 131
    .line 132
    return-object p0

    .line 133
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
