.class public final Lxw/m;
.super Lxw/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:[Lxw/u;

.field public final synthetic d:I

.field public final e:Lxw/h;


# direct methods
.method public constructor <init>(Lxw/h;Ljava/lang/String;[Lxw/u;II)V
    .locals 0

    .line 1
    iput p5, p0, Lxw/m;->d:I

    .line 2
    .line 3
    invoke-direct {p0, p2, p4}, Lxw/n;-><init>(Ljava/lang/String;I)V

    .line 4
    .line 5
    .line 6
    const/4 p2, 0x0

    .line 7
    invoke-static {p3, p2}, Lxw/f;->a([Lxw/u;Z)V

    .line 8
    .line 9
    .line 10
    iput-object p3, p0, Lxw/m;->c:[Lxw/u;

    .line 11
    .line 12
    iput-object p1, p0, Lxw/m;->e:Lxw/h;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V
    .locals 11

    .line 1
    iget v0, p0, Lxw/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxw/n;->a:Ljava/lang/String;

    .line 7
    .line 8
    iget v1, p0, Lxw/n;->b:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    invoke-virtual {p1, p2, v0, v1, v2}, Lxw/v;->b(Lxw/s;Ljava/lang/String;IZ)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    if-nez v0, :cond_0

    .line 16
    .line 17
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 18
    .line 19
    :cond_0
    move-object v4, v0

    .line 20
    iget-object v0, p0, Lxw/m;->e:Lxw/h;

    .line 21
    .line 22
    iget-object v0, v0, Lxw/h;->a:Lxw/e;

    .line 23
    .line 24
    invoke-virtual {v0, v4}, Lxw/e;->g(Ljava/lang/Object;)Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    if-eqz v0, :cond_2

    .line 29
    .line 30
    const/4 v1, 0x0

    .line 31
    move v3, v1

    .line 32
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v4

    .line 36
    if-eqz v4, :cond_4

    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v6

    .line 42
    if-nez v3, :cond_1

    .line 43
    .line 44
    move v9, v2

    .line 45
    goto :goto_1

    .line 46
    :cond_1
    move v9, v1

    .line 47
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 48
    .line 49
    .line 50
    move-result v4

    .line 51
    xor-int/lit8 v10, v4, 0x1

    .line 52
    .line 53
    add-int/lit8 v8, v3, 0x1

    .line 54
    .line 55
    new-instance v5, Lxw/s;

    .line 56
    .line 57
    move-object v7, p2

    .line 58
    invoke-direct/range {v5 .. v10}, Lxw/s;-><init>(Ljava/lang/Object;Lxw/s;IZZ)V

    .line 59
    .line 60
    .line 61
    move-object p2, v5

    .line 62
    move-object v5, v7

    .line 63
    invoke-virtual {p0, p1, p2, p3}, Lxw/m;->b(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V

    .line 64
    .line 65
    .line 66
    move-object p2, v5

    .line 67
    move v3, v8

    .line 68
    goto :goto_0

    .line 69
    :cond_2
    move-object v5, p2

    .line 70
    instance-of p2, v4, Ljava/lang/Boolean;

    .line 71
    .line 72
    if-eqz p2, :cond_3

    .line 73
    .line 74
    check-cast v4, Ljava/lang/Boolean;

    .line 75
    .line 76
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 77
    .line 78
    .line 79
    move-result p2

    .line 80
    if-eqz p2, :cond_4

    .line 81
    .line 82
    invoke-virtual {p0, p1, v5, p3}, Lxw/m;->b(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_3
    new-instance v3, Lxw/s;

    .line 87
    .line 88
    const/4 v6, 0x0

    .line 89
    const/4 v7, 0x0

    .line 90
    const/4 v8, 0x0

    .line 91
    invoke-direct/range {v3 .. v8}, Lxw/s;-><init>(Ljava/lang/Object;Lxw/s;IZZ)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {p0, p1, v3, p3}, Lxw/m;->b(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V

    .line 95
    .line 96
    .line 97
    :cond_4
    :goto_2
    return-void

    .line 98
    :pswitch_0
    move-object v5, p2

    .line 99
    iget p2, p0, Lxw/n;->b:I

    .line 100
    .line 101
    const/4 v0, 0x1

    .line 102
    iget-object v1, p0, Lxw/n;->a:Ljava/lang/String;

    .line 103
    .line 104
    invoke-virtual {p1, v5, v1, p2, v0}, Lxw/v;->b(Lxw/s;Ljava/lang/String;IZ)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object p2

    .line 108
    if-nez p2, :cond_5

    .line 109
    .line 110
    sget-object p2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 111
    .line 112
    :cond_5
    iget-object v0, p0, Lxw/m;->e:Lxw/h;

    .line 113
    .line 114
    iget-object v0, v0, Lxw/h;->a:Lxw/e;

    .line 115
    .line 116
    invoke-virtual {v0, p2}, Lxw/e;->g(Ljava/lang/Object;)Ljava/util/Iterator;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    if-eqz v0, :cond_6

    .line 121
    .line 122
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 123
    .line 124
    .line 125
    move-result p2

    .line 126
    if-nez p2, :cond_7

    .line 127
    .line 128
    invoke-virtual {p0, p1, v5, p3}, Lxw/m;->b(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V

    .line 129
    .line 130
    .line 131
    goto :goto_3

    .line 132
    :cond_6
    instance-of v0, p2, Ljava/lang/Boolean;

    .line 133
    .line 134
    if-eqz v0, :cond_7

    .line 135
    .line 136
    check-cast p2, Ljava/lang/Boolean;

    .line 137
    .line 138
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 139
    .line 140
    .line 141
    move-result p2

    .line 142
    if-nez p2, :cond_7

    .line 143
    .line 144
    invoke-virtual {p0, p1, v5, p3}, Lxw/m;->b(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V

    .line 145
    .line 146
    .line 147
    :cond_7
    :goto_3
    return-void

    .line 148
    nop

    .line 149
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lxw/m;->c:[Lxw/u;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    if-ge v1, v0, :cond_0

    .line 6
    .line 7
    aget-object v2, p0, v1

    .line 8
    .line 9
    invoke-virtual {v2, p1, p2, p3}, Lxw/u;->a(Lxw/v;Lxw/s;Ljava/io/StringWriter;)V

    .line 10
    .line 11
    .line 12
    add-int/lit8 v1, v1, 0x1

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, Lxw/m;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v1, "Section("

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v1, p0, Lxw/n;->a:Ljava/lang/String;

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string v1, ":"

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    iget v1, p0, Lxw/n;->b:I

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, "): "

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lxw/m;->c:[Lxw/u;

    .line 34
    .line 35
    invoke-static {p0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v1, "Inverted("

    .line 50
    .line 51
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    iget-object v1, p0, Lxw/n;->a:Ljava/lang/String;

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ":"

    .line 60
    .line 61
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    iget v1, p0, Lxw/n;->b:I

    .line 65
    .line 66
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    const-string v1, "): "

    .line 70
    .line 71
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    iget-object p0, p0, Lxw/m;->c:[Lxw/u;

    .line 75
    .line 76
    invoke-static {p0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object p0

    .line 87
    return-object p0

    .line 88
    nop

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
