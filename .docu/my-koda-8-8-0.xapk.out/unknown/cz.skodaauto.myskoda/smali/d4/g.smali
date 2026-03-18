.class public final Ld4/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# static fields
.field public static final e:Ld4/g;

.field public static final f:Ld4/g;

.field public static final g:Ld4/g;


# instance fields
.field public final synthetic d:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ld4/g;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ld4/g;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ld4/g;->e:Ld4/g;

    .line 8
    .line 9
    new-instance v0, Ld4/g;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Ld4/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Ld4/g;->f:Ld4/g;

    .line 16
    .line 17
    new-instance v0, Ld4/g;

    .line 18
    .line 19
    const/4 v1, 0x2

    .line 20
    invoke-direct {v0, v1}, Ld4/g;-><init>(I)V

    .line 21
    .line 22
    .line 23
    sput-object v0, Ld4/g;->g:Ld4/g;

    .line 24
    .line 25
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Ld4/g;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 1

    .line 1
    iget p0, p0, Ld4/g;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Llx0/l;

    .line 7
    .line 8
    check-cast p2, Llx0/l;

    .line 9
    .line 10
    iget-object p0, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Ld3/c;

    .line 13
    .line 14
    iget p0, p0, Ld3/c;->b:F

    .line 15
    .line 16
    iget-object v0, p2, Llx0/l;->d:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v0, Ld3/c;

    .line 19
    .line 20
    iget v0, v0, Ld3/c;->b:F

    .line 21
    .line 22
    invoke-static {p0, v0}, Ljava/lang/Float;->compare(FF)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    iget-object p0, p1, Llx0/l;->d:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Ld3/c;

    .line 32
    .line 33
    iget p0, p0, Ld3/c;->d:F

    .line 34
    .line 35
    iget-object p1, p2, Llx0/l;->d:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p1, Ld3/c;

    .line 38
    .line 39
    iget p1, p1, Ld3/c;->d:F

    .line 40
    .line 41
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    :goto_0
    return p0

    .line 46
    :pswitch_0
    check-cast p1, Ld4/q;

    .line 47
    .line 48
    check-cast p2, Ld4/q;

    .line 49
    .line 50
    invoke-virtual {p1}, Ld4/q;->h()Ld3/c;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p2}, Ld4/q;->h()Ld3/c;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    iget p2, p1, Ld3/c;->c:F

    .line 59
    .line 60
    iget v0, p0, Ld3/c;->c:F

    .line 61
    .line 62
    invoke-static {p2, v0}, Ljava/lang/Float;->compare(FF)I

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    if-eqz p2, :cond_1

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_1
    iget p2, p0, Ld3/c;->b:F

    .line 70
    .line 71
    iget v0, p1, Ld3/c;->b:F

    .line 72
    .line 73
    invoke-static {p2, v0}, Ljava/lang/Float;->compare(FF)I

    .line 74
    .line 75
    .line 76
    move-result p2

    .line 77
    if-eqz p2, :cond_2

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_2
    iget p2, p0, Ld3/c;->d:F

    .line 81
    .line 82
    iget v0, p1, Ld3/c;->d:F

    .line 83
    .line 84
    invoke-static {p2, v0}, Ljava/lang/Float;->compare(FF)I

    .line 85
    .line 86
    .line 87
    move-result p2

    .line 88
    if-eqz p2, :cond_3

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_3
    iget p1, p1, Ld3/c;->a:F

    .line 92
    .line 93
    iget p0, p0, Ld3/c;->a:F

    .line 94
    .line 95
    invoke-static {p1, p0}, Ljava/lang/Float;->compare(FF)I

    .line 96
    .line 97
    .line 98
    move-result p2

    .line 99
    :goto_1
    return p2

    .line 100
    :pswitch_1
    check-cast p1, Ld4/q;

    .line 101
    .line 102
    check-cast p2, Ld4/q;

    .line 103
    .line 104
    invoke-virtual {p1}, Ld4/q;->h()Ld3/c;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-virtual {p2}, Ld4/q;->h()Ld3/c;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    iget p2, p0, Ld3/c;->a:F

    .line 113
    .line 114
    iget v0, p1, Ld3/c;->a:F

    .line 115
    .line 116
    invoke-static {p2, v0}, Ljava/lang/Float;->compare(FF)I

    .line 117
    .line 118
    .line 119
    move-result p2

    .line 120
    if-eqz p2, :cond_4

    .line 121
    .line 122
    goto :goto_2

    .line 123
    :cond_4
    iget p2, p0, Ld3/c;->b:F

    .line 124
    .line 125
    iget v0, p1, Ld3/c;->b:F

    .line 126
    .line 127
    invoke-static {p2, v0}, Ljava/lang/Float;->compare(FF)I

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    if-eqz p2, :cond_5

    .line 132
    .line 133
    goto :goto_2

    .line 134
    :cond_5
    iget p2, p0, Ld3/c;->d:F

    .line 135
    .line 136
    iget v0, p1, Ld3/c;->d:F

    .line 137
    .line 138
    invoke-static {p2, v0}, Ljava/lang/Float;->compare(FF)I

    .line 139
    .line 140
    .line 141
    move-result p2

    .line 142
    if-eqz p2, :cond_6

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_6
    iget p0, p0, Ld3/c;->c:F

    .line 146
    .line 147
    iget p1, p1, Ld3/c;->c:F

    .line 148
    .line 149
    invoke-static {p0, p1}, Ljava/lang/Float;->compare(FF)I

    .line 150
    .line 151
    .line 152
    move-result p2

    .line 153
    :goto_2
    return p2

    .line 154
    nop

    .line 155
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
