.class public abstract Luz0/m0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/a;


# instance fields
.field public final synthetic a:I

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lhy0/d;)V
    .locals 2

    const/4 v0, 0x1

    iput v0, p0, Luz0/m0;->a:I

    const-string v0, "baseClass"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Luz0/m0;->b:Ljava/lang/Object;

    .line 5
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "JsonContentPolymorphicSerializer<"

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-interface {p1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p1, 0x3e

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    sget-object v0, Lsz0/c;->c:Lsz0/c;

    const/4 v1, 0x0

    new-array v1, v1, [Lsz0/g;

    invoke-static {p1, v0, v1}, Lkp/x8;->e(Ljava/lang/String;Lkp/y8;[Lsz0/g;)Lsz0/h;

    move-result-object p1

    iput-object p1, p0, Luz0/m0;->c:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lqz0/a;Lqz0/a;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Luz0/m0;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Luz0/m0;->b:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Luz0/m0;->c:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public abstract a(Ljava/lang/Object;)Ljava/lang/Object;
.end method

.method public abstract b(Ljava/lang/Object;)Ljava/lang/Object;
.end method

.method public abstract c(Lvz0/n;)Lqz0/a;
.end method

.method public abstract d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
.end method

.method public final deserialize(Ltz0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget v0, p0, Luz0/m0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Llp/qc;->b(Ltz0/c;)Lvz0/l;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    invoke-interface {p1}, Lvz0/l;->h()Lvz0/n;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    invoke-virtual {p0, v0}, Luz0/m0;->c(Lvz0/n;)Lqz0/a;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string v1, "null cannot be cast to non-null type kotlinx.serialization.KSerializer<T of kotlinx.serialization.json.JsonContentPolymorphicSerializer>"

    .line 19
    .line 20
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    check-cast p0, Lqz0/a;

    .line 24
    .line 25
    invoke-interface {p1}, Lvz0/l;->z()Lvz0/d;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    check-cast p0, Lqz0/a;

    .line 30
    .line 31
    invoke-virtual {p1, p0, v0}, Lvz0/d;->a(Lqz0/a;Lvz0/n;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_0
    sget-object v0, Luz0/b1;->c:Ljava/lang/Object;

    .line 37
    .line 38
    iget-object v1, p0, Luz0/m0;->c:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Lqz0/a;

    .line 41
    .line 42
    iget-object v2, p0, Luz0/m0;->b:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v2, Lqz0/a;

    .line 45
    .line 46
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 47
    .line 48
    .line 49
    move-result-object v3

    .line 50
    invoke-interface {p1, v3}, Ltz0/c;->a(Lsz0/g;)Ltz0/a;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    move-object v4, v0

    .line 55
    move-object v5, v4

    .line 56
    :goto_0
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    invoke-interface {p1, v6}, Ltz0/a;->E(Lsz0/g;)I

    .line 61
    .line 62
    .line 63
    move-result v6

    .line 64
    const/4 v7, -0x1

    .line 65
    if-eq v6, v7, :cond_2

    .line 66
    .line 67
    const/4 v7, 0x0

    .line 68
    if-eqz v6, :cond_1

    .line 69
    .line 70
    const/4 v5, 0x1

    .line 71
    if-ne v6, v5, :cond_0

    .line 72
    .line 73
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 74
    .line 75
    .line 76
    move-result-object v6

    .line 77
    move-object v8, v1

    .line 78
    check-cast v8, Lqz0/a;

    .line 79
    .line 80
    invoke-interface {p1, v6, v5, v8, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v5

    .line 84
    goto :goto_0

    .line 85
    :cond_0
    new-instance p0, Lqz0/h;

    .line 86
    .line 87
    const-string p1, "Invalid index: "

    .line 88
    .line 89
    invoke-static {v6, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0

    .line 97
    :cond_1
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    const/4 v6, 0x0

    .line 102
    move-object v8, v2

    .line 103
    check-cast v8, Lqz0/a;

    .line 104
    .line 105
    invoke-interface {p1, v4, v6, v8, v7}, Ltz0/a;->r(Lsz0/g;ILqz0/a;Ljava/lang/Object;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    goto :goto_0

    .line 110
    :cond_2
    if-eq v4, v0, :cond_4

    .line 111
    .line 112
    if-eq v5, v0, :cond_3

    .line 113
    .line 114
    invoke-virtual {p0, v4, v5}, Luz0/m0;->d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-interface {p1, v3}, Ltz0/a;->b(Lsz0/g;)V

    .line 119
    .line 120
    .line 121
    return-object p0

    .line 122
    :cond_3
    new-instance p0, Lqz0/h;

    .line 123
    .line 124
    const-string p1, "Element \'value\' is missing"

    .line 125
    .line 126
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    :cond_4
    new-instance p0, Lqz0/h;

    .line 131
    .line 132
    const-string p1, "Element \'key\' is missing"

    .line 133
    .line 134
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw p0

    .line 138
    nop

    .line 139
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public getDescriptor()Lsz0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Luz0/m0;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lsz0/h;

    .line 4
    .line 5
    return-object p0
.end method

.method public final serialize(Ltz0/d;Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget v0, p0, Luz0/m0;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v0, "value"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p1}, Ltz0/d;->c()Lwq/f;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object p0, p0, Luz0/m0;->b:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Lhy0/d;

    .line 18
    .line 19
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 20
    .line 21
    .line 22
    const-string v0, "baseClass"

    .line 23
    .line 24
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p0, p2}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 v0, 0x1

    .line 35
    const/4 v1, 0x0

    .line 36
    invoke-static {v0, v1}, Lkotlin/jvm/internal/j0;->g(ILjava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    :goto_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 44
    .line 45
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-static {v0}, Ljp/mg;->f(Lhy0/d;)Lqz0/a;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    if-eqz v0, :cond_1

    .line 54
    .line 55
    check-cast v0, Lqz0/a;

    .line 56
    .line 57
    check-cast v0, Lqz0/a;

    .line 58
    .line 59
    invoke-interface {v0, p1, p2}, Lqz0/a;->serialize(Ltz0/d;Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_1
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    invoke-virtual {v1, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    invoke-interface {p1}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p2

    .line 75
    if-nez p2, :cond_2

    .line 76
    .line 77
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    const-string v0, "in the scope of \'"

    .line 84
    .line 85
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const/16 p0, 0x27

    .line 96
    .line 97
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    new-instance p1, Lqz0/h;

    .line 105
    .line 106
    const-string v0, "\' is not registered for polymorphic serialization "

    .line 107
    .line 108
    const-string v1, ".\nMark the base class as \'sealed\' or register the serializer explicitly."

    .line 109
    .line 110
    const-string v2, "Class \'"

    .line 111
    .line 112
    invoke-static {v2, p2, v0, p0, v1}, Lu/w;->g(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    throw p1

    .line 120
    :pswitch_0
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    invoke-interface {p1, v0}, Ltz0/d;->a(Lsz0/g;)Ltz0/b;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    iget-object v1, p0, Luz0/m0;->b:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v1, Lqz0/a;

    .line 135
    .line 136
    check-cast v1, Lqz0/a;

    .line 137
    .line 138
    invoke-virtual {p0, p2}, Luz0/m0;->a(Ljava/lang/Object;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v2

    .line 142
    const/4 v3, 0x0

    .line 143
    invoke-interface {p1, v0, v3, v1, v2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 147
    .line 148
    .line 149
    move-result-object v0

    .line 150
    iget-object v1, p0, Luz0/m0;->c:Ljava/lang/Object;

    .line 151
    .line 152
    check-cast v1, Lqz0/a;

    .line 153
    .line 154
    check-cast v1, Lqz0/a;

    .line 155
    .line 156
    invoke-virtual {p0, p2}, Luz0/m0;->b(Ljava/lang/Object;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object p2

    .line 160
    const/4 v2, 0x1

    .line 161
    invoke-interface {p1, v0, v2, v1, p2}, Ltz0/b;->k(Lsz0/g;ILqz0/a;Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    invoke-interface {p0}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 165
    .line 166
    .line 167
    move-result-object p0

    .line 168
    invoke-interface {p1, p0}, Ltz0/b;->b(Lsz0/g;)V

    .line 169
    .line 170
    .line 171
    return-void

    .line 172
    nop

    .line 173
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
