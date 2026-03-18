.class public final Li91/l1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lt4/c;

.field public final b:F

.field public final c:Li91/r2;

.field public d:F

.field public e:F

.field public final f:F

.field public final g:Ll2/j1;

.field public final h:Ll2/j1;

.field public final i:Ll2/j1;


# direct methods
.method public constructor <init>(Lt4/c;FLi91/r2;)V
    .locals 2

    .line 1
    const-string v0, "currentLocalDensity"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "bottomSheetState"

    .line 7
    .line 8
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Li91/l1;->a:Lt4/c;

    .line 15
    .line 16
    iput p2, p0, Li91/l1;->b:F

    .line 17
    .line 18
    iput-object p3, p0, Li91/l1;->c:Li91/r2;

    .line 19
    .line 20
    const/high16 p1, 0x7fc00000    # Float.NaN

    .line 21
    .line 22
    iput p1, p0, Li91/l1;->d:F

    .line 23
    .line 24
    iput p1, p0, Li91/l1;->e:F

    .line 25
    .line 26
    const/4 p1, 0x1

    .line 27
    int-to-float p1, p1

    .line 28
    iput p1, p0, Li91/l1;->f:F

    .line 29
    .line 30
    invoke-virtual {p3}, Li91/r2;->a()F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    new-instance v1, Lt4/f;

    .line 35
    .line 36
    invoke-direct {v1, v0}, Lt4/f;-><init>(F)V

    .line 37
    .line 38
    .line 39
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    iput-object v0, p0, Li91/l1;->g:Ll2/j1;

    .line 44
    .line 45
    iget-object v0, p3, Li91/r2;->d:Ll2/j1;

    .line 46
    .line 47
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    check-cast v0, Lt4/f;

    .line 52
    .line 53
    iget v0, v0, Lt4/f;->d:F

    .line 54
    .line 55
    sub-float/2addr p2, v0

    .line 56
    sub-float/2addr p2, p1

    .line 57
    new-instance p1, Lt4/f;

    .line 58
    .line 59
    invoke-direct {p1, p2}, Lt4/f;-><init>(F)V

    .line 60
    .line 61
    .line 62
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    iput-object p1, p0, Li91/l1;->h:Ll2/j1;

    .line 67
    .line 68
    invoke-virtual {p3}, Li91/r2;->c()Li91/s2;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    if-nez p1, :cond_0

    .line 73
    .line 74
    sget-object p1, Li91/s2;->e:Li91/s2;

    .line 75
    .line 76
    :cond_0
    invoke-virtual {p0, p1}, Li91/l1;->b(Li91/s2;)F

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    new-instance p2, Lt4/f;

    .line 81
    .line 82
    invoke-direct {p2, p1}, Lt4/f;-><init>(F)V

    .line 83
    .line 84
    .line 85
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    iput-object p1, p0, Li91/l1;->i:Ll2/j1;

    .line 90
    .line 91
    return-void
.end method


# virtual methods
.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Li91/l1;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt4/f;

    .line 8
    .line 9
    iget p0, p0, Lt4/f;->d:F

    .line 10
    .line 11
    return p0
.end method

.method public final b(Li91/s2;)F
    .locals 1

    .line 1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_3

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p1, v0, :cond_2

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    if-eq p1, v0, :cond_1

    .line 12
    .line 13
    const/4 p0, 0x3

    .line 14
    if-ne p1, p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    int-to-float p0, p0

    .line 18
    return p0

    .line 19
    :cond_0
    new-instance p0, La8/r0;

    .line 20
    .line 21
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    iget-object p0, p0, Li91/l1;->h:Ll2/j1;

    .line 26
    .line 27
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lt4/f;

    .line 32
    .line 33
    iget p0, p0, Lt4/f;->d:F

    .line 34
    .line 35
    return p0

    .line 36
    :cond_2
    iget-object p0, p0, Li91/l1;->g:Ll2/j1;

    .line 37
    .line 38
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    check-cast p0, Lt4/f;

    .line 43
    .line 44
    iget p0, p0, Lt4/f;->d:F

    .line 45
    .line 46
    return p0

    .line 47
    :cond_3
    iget p1, p0, Li91/l1;->e:F

    .line 48
    .line 49
    new-instance v0, Lt4/f;

    .line 50
    .line 51
    invoke-direct {v0, p1}, Lt4/f;-><init>(F)V

    .line 52
    .line 53
    .line 54
    iget-object p0, p0, Li91/l1;->c:Li91/r2;

    .line 55
    .line 56
    invoke-virtual {p0}, Li91/r2;->b()F

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    new-instance p1, Lt4/f;

    .line 61
    .line 62
    invoke-direct {p1, p0}, Lt4/f;-><init>(F)V

    .line 63
    .line 64
    .line 65
    invoke-static {v0, p1}, Ljp/vc;->e(Lt4/f;Ljava/lang/Comparable;)Ljava/lang/Comparable;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    check-cast p0, Lt4/f;

    .line 70
    .line 71
    iget p0, p0, Lt4/f;->d:F

    .line 72
    .line 73
    return p0
.end method

.method public final c()Z
    .locals 1

    .line 1
    iget-object v0, p0, Li91/l1;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lt4/f;

    .line 8
    .line 9
    iget v0, v0, Lt4/f;->d:F

    .line 10
    .line 11
    iget-object p0, p0, Li91/l1;->h:Ll2/j1;

    .line 12
    .line 13
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lt4/f;

    .line 18
    .line 19
    iget p0, p0, Lt4/f;->d:F

    .line 20
    .line 21
    invoke-static {v0, p0}, Ljava/lang/Float;->compare(FF)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-ltz p0, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_0
    const/4 p0, 0x0

    .line 30
    return p0
.end method

.method public final d(F)V
    .locals 3

    .line 1
    iget-object v0, p0, Li91/l1;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Lt4/f;

    .line 8
    .line 9
    iget v1, v1, Lt4/f;->d:F

    .line 10
    .line 11
    iget-object p0, p0, Li91/l1;->h:Ll2/j1;

    .line 12
    .line 13
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lt4/f;

    .line 18
    .line 19
    iget p0, p0, Lt4/f;->d:F

    .line 20
    .line 21
    invoke-static {v1, p0}, Ljava/lang/Float;->compare(FF)I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-lez p0, :cond_0

    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v1, "onDrag delta: "

    .line 31
    .line 32
    invoke-direct {p0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-static {p1}, Lt4/f;->b(F)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, " internalPeekHeight: "

    .line 43
    .line 44
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Lt4/f;

    .line 52
    .line 53
    iget v1, v1, Lt4/f;->d:F

    .line 54
    .line 55
    invoke-static {v1}, Lt4/f;->b(F)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    const-string v1, ", "

    .line 63
    .line 64
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    sget-object v2, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 72
    .line 73
    invoke-virtual {v2, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    check-cast p0, Lt4/f;

    .line 81
    .line 82
    iget p0, p0, Lt4/f;->d:F

    .line 83
    .line 84
    sub-float/2addr p0, p1

    .line 85
    const/4 v2, 0x0

    .line 86
    int-to-float v2, v2

    .line 87
    invoke-static {p0, v2}, Ljava/lang/Float;->compare(FF)I

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    if-gez p0, :cond_1

    .line 92
    .line 93
    new-instance p0, Lt4/f;

    .line 94
    .line 95
    invoke-direct {p0, v2}, Lt4/f;-><init>(F)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v0, p0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    return-void

    .line 102
    :cond_1
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    check-cast p0, Lt4/f;

    .line 107
    .line 108
    iget p0, p0, Lt4/f;->d:F

    .line 109
    .line 110
    sub-float/2addr p0, p1

    .line 111
    new-instance p1, Lt4/f;

    .line 112
    .line 113
    invoke-direct {p1, p0}, Lt4/f;-><init>(F)V

    .line 114
    .line 115
    .line 116
    invoke-virtual {v0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    new-instance p0, Ljava/lang/StringBuilder;

    .line 120
    .line 121
    const-string p1, "onDrag internalPeekHeight: "

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    check-cast p1, Lt4/f;

    .line 131
    .line 132
    iget p1, p1, Lt4/f;->d:F

    .line 133
    .line 134
    invoke-static {p1}, Lt4/f;->b(F)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p1

    .line 138
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 142
    .line 143
    .line 144
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    sget-object p1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 149
    .line 150
    invoke-virtual {p1, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    return-void
.end method

.method public final e()V
    .locals 7

    .line 1
    iget-object v0, p0, Li91/l1;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lt4/f;

    .line 8
    .line 9
    iget v0, v0, Lt4/f;->d:F

    .line 10
    .line 11
    new-instance v1, Lt4/f;

    .line 12
    .line 13
    invoke-direct {v1, v0}, Lt4/f;-><init>(F)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Li91/l1;->c:Li91/r2;

    .line 17
    .line 18
    invoke-virtual {v0}, Li91/r2;->b()F

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    new-instance v3, Lt4/f;

    .line 23
    .line 24
    invoke-direct {v3, v2}, Lt4/f;-><init>(F)V

    .line 25
    .line 26
    .line 27
    invoke-static {v1, v3}, Ljp/vc;->d(Lt4/f;Lt4/f;)Ljava/lang/Comparable;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Lt4/f;

    .line 32
    .line 33
    iget v1, v1, Lt4/f;->d:F

    .line 34
    .line 35
    new-instance v2, Lt4/f;

    .line 36
    .line 37
    invoke-direct {v2, v1}, Lt4/f;-><init>(F)V

    .line 38
    .line 39
    .line 40
    iget-object v1, p0, Li91/l1;->h:Ll2/j1;

    .line 41
    .line 42
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    check-cast v3, Ljava/lang/Comparable;

    .line 47
    .line 48
    invoke-static {v2, v3}, Ljp/vc;->e(Lt4/f;Ljava/lang/Comparable;)Ljava/lang/Comparable;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    check-cast v2, Lt4/f;

    .line 53
    .line 54
    iget v2, v2, Lt4/f;->d:F

    .line 55
    .line 56
    iget-object v3, p0, Li91/l1;->g:Ll2/j1;

    .line 57
    .line 58
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v4

    .line 62
    check-cast v4, Lt4/f;

    .line 63
    .line 64
    iget v4, v4, Lt4/f;->d:F

    .line 65
    .line 66
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v5

    .line 70
    check-cast v5, Lt4/f;

    .line 71
    .line 72
    iget v5, v5, Lt4/f;->d:F

    .line 73
    .line 74
    invoke-static {v4, v5}, Lt4/f;->a(FF)Z

    .line 75
    .line 76
    .line 77
    move-result v4

    .line 78
    const/4 v5, 0x2

    .line 79
    if-eqz v4, :cond_0

    .line 80
    .line 81
    invoke-virtual {v0}, Li91/r2;->b()F

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    check-cast v4, Lt4/f;

    .line 90
    .line 91
    iget v4, v4, Lt4/f;->d:F

    .line 92
    .line 93
    invoke-virtual {v0}, Li91/r2;->b()F

    .line 94
    .line 95
    .line 96
    move-result v6

    .line 97
    sub-float/2addr v4, v6

    .line 98
    int-to-float v6, v5

    .line 99
    div-float/2addr v4, v6

    .line 100
    add-float/2addr v4, v1

    .line 101
    goto :goto_0

    .line 102
    :cond_0
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v4

    .line 106
    check-cast v4, Lt4/f;

    .line 107
    .line 108
    iget v4, v4, Lt4/f;->d:F

    .line 109
    .line 110
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    check-cast v1, Lt4/f;

    .line 115
    .line 116
    iget v1, v1, Lt4/f;->d:F

    .line 117
    .line 118
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v6

    .line 122
    check-cast v6, Lt4/f;

    .line 123
    .line 124
    iget v6, v6, Lt4/f;->d:F

    .line 125
    .line 126
    sub-float/2addr v1, v6

    .line 127
    int-to-float v6, v5

    .line 128
    div-float/2addr v1, v6

    .line 129
    add-float/2addr v4, v1

    .line 130
    :goto_0
    invoke-static {v2, v4}, Ljava/lang/Float;->compare(FF)I

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-ltz v1, :cond_1

    .line 135
    .line 136
    sget-object v0, Li91/s2;->f:Li91/s2;

    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_1
    invoke-virtual {v0}, Li91/r2;->b()F

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v3

    .line 147
    check-cast v3, Lt4/f;

    .line 148
    .line 149
    iget v3, v3, Lt4/f;->d:F

    .line 150
    .line 151
    invoke-virtual {v0}, Li91/r2;->b()F

    .line 152
    .line 153
    .line 154
    move-result v0

    .line 155
    sub-float/2addr v3, v0

    .line 156
    int-to-float v0, v5

    .line 157
    div-float/2addr v3, v0

    .line 158
    add-float/2addr v3, v1

    .line 159
    invoke-static {v2, v3}, Ljava/lang/Float;->compare(FF)I

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    if-gtz v0, :cond_2

    .line 164
    .line 165
    sget-object v0, Li91/s2;->d:Li91/s2;

    .line 166
    .line 167
    goto :goto_1

    .line 168
    :cond_2
    sget-object v0, Li91/s2;->e:Li91/s2;

    .line 169
    .line 170
    :goto_1
    invoke-virtual {p0, v0}, Li91/l1;->g(Li91/s2;)V

    .line 171
    .line 172
    .line 173
    const/high16 v0, 0x7fc00000    # Float.NaN

    .line 174
    .line 175
    iput v0, p0, Li91/l1;->d:F

    .line 176
    .line 177
    return-void
.end method

.method public final f()V
    .locals 1

    .line 1
    iget-object v0, p0, Li91/l1;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lt4/f;

    .line 8
    .line 9
    iget v0, v0, Lt4/f;->d:F

    .line 10
    .line 11
    iput v0, p0, Li91/l1;->d:F

    .line 12
    .line 13
    iget-object p0, p0, Li91/l1;->c:Li91/r2;

    .line 14
    .line 15
    iget-object p0, p0, Li91/r2;->e:Ll2/j1;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    return-void
.end method

.method public final g(Li91/s2;)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Li91/l1;->b(Li91/s2;)F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    new-instance v1, Lt4/f;

    .line 6
    .line 7
    invoke-direct {v1, v0}, Lt4/f;-><init>(F)V

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Li91/l1;->i:Ll2/j1;

    .line 11
    .line 12
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    iget-object p0, p0, Li91/l1;->c:Li91/r2;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Li91/r2;->f(Li91/s2;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MaulInternalBottomSheetState - currentState: "

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Li91/l1;->c:Li91/r2;

    .line 9
    .line 10
    invoke-virtual {v1}, Li91/r2;->c()Li91/s2;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 v1, 0x0

    .line 22
    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v1, " internalDefaultHeight: "

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object v1, p0, Li91/l1;->g:Ll2/j1;

    .line 31
    .line 32
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    check-cast v1, Lt4/f;

    .line 37
    .line 38
    iget v1, v1, Lt4/f;->d:F

    .line 39
    .line 40
    const-string v2, ", peekHeight: "

    .line 41
    .line 42
    invoke-static {v1, v2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->t(FLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 43
    .line 44
    .line 45
    iget-object v1, p0, Li91/l1;->i:Ll2/j1;

    .line 46
    .line 47
    invoke-virtual {v1}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Lt4/f;

    .line 52
    .line 53
    iget v1, v1, Lt4/f;->d:F

    .line 54
    .line 55
    const-string v2, ", maxHeight: "

    .line 56
    .line 57
    invoke-static {v1, v2, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->t(FLjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 58
    .line 59
    .line 60
    iget-object p0, p0, Li91/l1;->h:Ll2/j1;

    .line 61
    .line 62
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lt4/f;

    .line 67
    .line 68
    iget p0, p0, Lt4/f;->d:F

    .line 69
    .line 70
    invoke-static {p0}, Lt4/f;->b(F)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    return-object p0
.end method
