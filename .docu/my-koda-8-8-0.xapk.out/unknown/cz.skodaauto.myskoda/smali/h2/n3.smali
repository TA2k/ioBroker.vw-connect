.class public final synthetic Lh2/n3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lh2/e8;

.field public final synthetic f:Ljava/util/Locale;


# direct methods
.method public synthetic constructor <init>(Lh2/e8;Ljava/util/Locale;I)V
    .locals 0

    .line 1
    iput p3, p0, Lh2/n3;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/n3;->e:Lh2/e8;

    .line 4
    .line 5
    iput-object p2, p0, Lh2/n3;->f:Ljava/util/Locale;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Lh2/n3;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/util/List;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance v0, Lh2/g4;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Ljava/lang/Long;

    .line 16
    .line 17
    const/4 v2, 0x1

    .line 18
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v3

    .line 22
    check-cast v3, Ljava/lang/Long;

    .line 23
    .line 24
    const/4 v4, 0x2

    .line 25
    invoke-interface {p1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    check-cast v4, Ljava/lang/Long;

    .line 30
    .line 31
    move v5, v2

    .line 32
    move-object v2, v3

    .line 33
    move-object v3, v4

    .line 34
    new-instance v4, Lgy0/j;

    .line 35
    .line 36
    const/4 v6, 0x3

    .line 37
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    const-string v7, "null cannot be cast to non-null type kotlin.Int"

    .line 42
    .line 43
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    check-cast v6, Ljava/lang/Integer;

    .line 47
    .line 48
    invoke-virtual {v6}, Ljava/lang/Integer;->intValue()I

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    const/4 v8, 0x4

    .line 53
    invoke-interface {p1, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v8

    .line 57
    invoke-static {v8, v7}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    check-cast v8, Ljava/lang/Integer;

    .line 61
    .line 62
    invoke-virtual {v8}, Ljava/lang/Integer;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result v8

    .line 66
    invoke-direct {v4, v6, v8, v5}, Lgy0/h;-><init>(III)V

    .line 67
    .line 68
    .line 69
    const/4 v5, 0x5

    .line 70
    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    invoke-static {p1, v7}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    check-cast p1, Ljava/lang/Integer;

    .line 78
    .line 79
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    iget-object v6, p0, Lh2/n3;->e:Lh2/e8;

    .line 84
    .line 85
    iget-object v7, p0, Lh2/n3;->f:Ljava/util/Locale;

    .line 86
    .line 87
    invoke-direct/range {v0 .. v7}, Lh2/g4;-><init>(Ljava/lang/Long;Ljava/lang/Long;Ljava/lang/Long;Lgy0/j;ILh2/e8;Ljava/util/Locale;)V

    .line 88
    .line 89
    .line 90
    return-object v0

    .line 91
    :pswitch_0
    new-instance v0, Lh2/o3;

    .line 92
    .line 93
    const/4 v1, 0x0

    .line 94
    invoke-interface {p1, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    check-cast v1, Ljava/lang/Long;

    .line 99
    .line 100
    const/4 v2, 0x1

    .line 101
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v3

    .line 105
    check-cast v3, Ljava/lang/Long;

    .line 106
    .line 107
    move v4, v2

    .line 108
    move-object v2, v3

    .line 109
    new-instance v3, Lgy0/j;

    .line 110
    .line 111
    const/4 v5, 0x2

    .line 112
    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v5

    .line 116
    const-string v6, "null cannot be cast to non-null type kotlin.Int"

    .line 117
    .line 118
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    check-cast v5, Ljava/lang/Integer;

    .line 122
    .line 123
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 124
    .line 125
    .line 126
    move-result v5

    .line 127
    const/4 v7, 0x3

    .line 128
    invoke-interface {p1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v7

    .line 132
    invoke-static {v7, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    check-cast v7, Ljava/lang/Integer;

    .line 136
    .line 137
    invoke-virtual {v7}, Ljava/lang/Integer;->intValue()I

    .line 138
    .line 139
    .line 140
    move-result v7

    .line 141
    invoke-direct {v3, v5, v7, v4}, Lgy0/h;-><init>(III)V

    .line 142
    .line 143
    .line 144
    const/4 v4, 0x4

    .line 145
    invoke-interface {p1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object p1

    .line 149
    invoke-static {p1, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 150
    .line 151
    .line 152
    check-cast p1, Ljava/lang/Integer;

    .line 153
    .line 154
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 155
    .line 156
    .line 157
    move-result v4

    .line 158
    iget-object v5, p0, Lh2/n3;->e:Lh2/e8;

    .line 159
    .line 160
    iget-object v6, p0, Lh2/n3;->f:Ljava/util/Locale;

    .line 161
    .line 162
    invoke-direct/range {v0 .. v6}, Lh2/o3;-><init>(Ljava/lang/Long;Ljava/lang/Long;Lgy0/j;ILh2/e8;Ljava/util/Locale;)V

    .line 163
    .line 164
    .line 165
    return-object v0

    .line 166
    nop

    .line 167
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
