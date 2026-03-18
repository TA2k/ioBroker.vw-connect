.class public abstract Lr0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public b:I

.field public c:I

.field public d:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;)V
    .locals 7

    .line 1
    const-string v0, "glAttachShader"

    .line 2
    .line 3
    const-string v1, "Could not link program: "

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    const/4 v2, -0x1

    .line 9
    iput v2, p0, Lr0/g;->b:I

    .line 10
    .line 11
    iput v2, p0, Lr0/g;->c:I

    .line 12
    .line 13
    iput v2, p0, Lr0/g;->d:I

    .line 14
    .line 15
    const v3, 0x8b31

    .line 16
    .line 17
    .line 18
    :try_start_0
    invoke-static {v3, p1}, Lr0/i;->k(ILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result p1
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_3

    .line 22
    const v3, 0x8b30

    .line 23
    .line 24
    .line 25
    :try_start_1
    invoke-static {v3, p2}, Lr0/i;->k(ILjava/lang/String;)I

    .line 26
    .line 27
    .line 28
    move-result p2
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_2

    .line 29
    :try_start_2
    invoke-static {}, Landroid/opengl/GLES20;->glCreateProgram()I

    .line 30
    .line 31
    .line 32
    move-result v3
    :try_end_2
    .catch Ljava/lang/IllegalStateException; {:try_start_2 .. :try_end_2} :catch_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_1

    .line 33
    :try_start_3
    const-string v4, "glCreateProgram"

    .line 34
    .line 35
    invoke-static {v4}, Lr0/i;->b(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-static {v3, p1}, Landroid/opengl/GLES20;->glAttachShader(II)V

    .line 39
    .line 40
    .line 41
    invoke-static {v0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-static {v3, p2}, Landroid/opengl/GLES20;->glAttachShader(II)V

    .line 45
    .line 46
    .line 47
    invoke-static {v0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    invoke-static {v3}, Landroid/opengl/GLES20;->glLinkProgram(I)V

    .line 51
    .line 52
    .line 53
    const/4 v0, 0x1

    .line 54
    new-array v4, v0, [I

    .line 55
    .line 56
    const v5, 0x8b82

    .line 57
    .line 58
    .line 59
    const/4 v6, 0x0

    .line 60
    invoke-static {v3, v5, v4, v6}, Landroid/opengl/GLES20;->glGetProgramiv(II[II)V

    .line 61
    .line 62
    .line 63
    aget v4, v4, v6

    .line 64
    .line 65
    if-ne v4, v0, :cond_0

    .line 66
    .line 67
    iput v3, p0, Lr0/g;->a:I
    :try_end_3
    .catch Ljava/lang/IllegalStateException; {:try_start_3 .. :try_end_3} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_3 .. :try_end_3} :catch_0

    .line 68
    .line 69
    invoke-virtual {p0}, Lr0/g;->a()V

    .line 70
    .line 71
    .line 72
    return-void

    .line 73
    :catch_0
    move-exception p0

    .line 74
    goto :goto_1

    .line 75
    :cond_0
    :try_start_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 76
    .line 77
    new-instance v0, Ljava/lang/StringBuilder;

    .line 78
    .line 79
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-static {v3}, Landroid/opengl/GLES20;->glGetProgramInfoLog(I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 94
    .line 95
    .line 96
    throw p0
    :try_end_4
    .catch Ljava/lang/IllegalStateException; {:try_start_4 .. :try_end_4} :catch_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_4 .. :try_end_4} :catch_0

    .line 97
    :catch_1
    move-exception p0

    .line 98
    move v3, v2

    .line 99
    goto :goto_1

    .line 100
    :catch_2
    move-exception p0

    .line 101
    move p2, v2

    .line 102
    :goto_0
    move v3, p2

    .line 103
    goto :goto_1

    .line 104
    :catch_3
    move-exception p0

    .line 105
    move p1, v2

    .line 106
    move p2, p1

    .line 107
    goto :goto_0

    .line 108
    :goto_1
    if-eq p1, v2, :cond_1

    .line 109
    .line 110
    invoke-static {p1}, Landroid/opengl/GLES20;->glDeleteShader(I)V

    .line 111
    .line 112
    .line 113
    :cond_1
    if-eq p2, v2, :cond_2

    .line 114
    .line 115
    invoke-static {p2}, Landroid/opengl/GLES20;->glDeleteShader(I)V

    .line 116
    .line 117
    .line 118
    :cond_2
    if-eq v3, v2, :cond_3

    .line 119
    .line 120
    invoke-static {v3}, Landroid/opengl/GLES20;->glDeleteProgram(I)V

    .line 121
    .line 122
    .line 123
    :cond_3
    throw p0
.end method


# virtual methods
.method public final a()V
    .locals 3

    .line 1
    iget v0, p0, Lr0/g;->a:I

    .line 2
    .line 3
    const-string v1, "aPosition"

    .line 4
    .line 5
    invoke-static {v0, v1}, Landroid/opengl/GLES20;->glGetAttribLocation(ILjava/lang/String;)I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    iput v2, p0, Lr0/g;->d:I

    .line 10
    .line 11
    invoke-static {v2, v1}, Lr0/i;->e(ILjava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v1, "uTransMatrix"

    .line 15
    .line 16
    invoke-static {v0, v1}, Landroid/opengl/GLES20;->glGetUniformLocation(ILjava/lang/String;)I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    iput v2, p0, Lr0/g;->b:I

    .line 21
    .line 22
    invoke-static {v2, v1}, Lr0/i;->e(ILjava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const-string v1, "uAlphaScale"

    .line 26
    .line 27
    invoke-static {v0, v1}, Landroid/opengl/GLES20;->glGetUniformLocation(ILjava/lang/String;)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    iput v0, p0, Lr0/g;->c:I

    .line 32
    .line 33
    invoke-static {v0, v1}, Lr0/i;->e(ILjava/lang/String;)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public b()V
    .locals 7

    .line 1
    iget v0, p0, Lr0/g;->a:I

    .line 2
    .line 3
    invoke-static {v0}, Landroid/opengl/GLES20;->glUseProgram(I)V

    .line 4
    .line 5
    .line 6
    const-string v0, "glUseProgram"

    .line 7
    .line 8
    invoke-static {v0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget v0, p0, Lr0/g;->d:I

    .line 12
    .line 13
    invoke-static {v0}, Landroid/opengl/GLES20;->glEnableVertexAttribArray(I)V

    .line 14
    .line 15
    .line 16
    const-string v0, "glEnableVertexAttribArray"

    .line 17
    .line 18
    invoke-static {v0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget v1, p0, Lr0/g;->d:I

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    sget-object v6, Lr0/i;->h:Ljava/nio/FloatBuffer;

    .line 25
    .line 26
    const/4 v2, 0x2

    .line 27
    const/16 v3, 0x1406

    .line 28
    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-static/range {v1 .. v6}, Landroid/opengl/GLES20;->glVertexAttribPointer(IIIZILjava/nio/Buffer;)V

    .line 31
    .line 32
    .line 33
    const-string v0, "glVertexAttribPointer"

    .line 34
    .line 35
    invoke-static {v0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    const/16 v0, 0x10

    .line 39
    .line 40
    new-array v0, v0, [F

    .line 41
    .line 42
    const/4 v1, 0x0

    .line 43
    invoke-static {v0, v1}, Landroid/opengl/Matrix;->setIdentityM([FI)V

    .line 44
    .line 45
    .line 46
    iget v2, p0, Lr0/g;->b:I

    .line 47
    .line 48
    const/4 v3, 0x1

    .line 49
    invoke-static {v2, v3, v1, v0, v1}, Landroid/opengl/GLES20;->glUniformMatrix4fv(IIZ[FI)V

    .line 50
    .line 51
    .line 52
    const-string v0, "glUniformMatrix4fv"

    .line 53
    .line 54
    invoke-static {v0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const/high16 v0, 0x3f800000    # 1.0f

    .line 58
    .line 59
    iget p0, p0, Lr0/g;->c:I

    .line 60
    .line 61
    invoke-static {p0, v0}, Landroid/opengl/GLES20;->glUniform1f(IF)V

    .line 62
    .line 63
    .line 64
    const-string p0, "glUniform1f"

    .line 65
    .line 66
    invoke-static {p0}, Lr0/i;->b(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    return-void
.end method
