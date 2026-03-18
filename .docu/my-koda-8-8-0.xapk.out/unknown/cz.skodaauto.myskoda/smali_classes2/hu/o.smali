.class public final Lhu/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lju/b;


# instance fields
.field public final synthetic d:I


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Lhu/o;->d:I

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static b(Lm6/u0;Lb3/g;Lpw0/a;Lay0/a;)Lm6/w;
    .locals 5

    .line 1
    sget-object v0, Lmx0/s;->d:Lmx0/s;

    .line 2
    .line 3
    :try_start_0
    const-string v1, "datastore_shared_counter"

    .line 4
    .line 5
    invoke-static {v1}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/UnsatisfiedLinkError; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 6
    .line 7
    .line 8
    new-instance v1, Lm6/w;

    .line 9
    .line 10
    new-instance v2, Lm6/b0;

    .line 11
    .line 12
    new-instance v3, La3/f;

    .line 13
    .line 14
    const/16 v4, 0x19

    .line 15
    .line 16
    invoke-direct {v3, p2, v4}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v2, p0, v3, p3}, Lm6/b0;-><init>(Lm6/u0;Lay0/k;Lay0/a;)V

    .line 20
    .line 21
    .line 22
    new-instance p0, Lk31/t;

    .line 23
    .line 24
    const/4 p3, 0x0

    .line 25
    const/16 v3, 0x13

    .line 26
    .line 27
    invoke-direct {p0, v0, p3, v3}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    invoke-static {p0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-direct {v1, v2, p0, p1, p2}, Lm6/w;-><init>(Lm6/b0;Ljava/util/List;Lm6/c;Lvy0/b0;)V

    .line 35
    .line 36
    .line 37
    return-object v1

    .line 38
    :catch_0
    invoke-static {p0, p1, v0, p2, p3}, Lfb/w;->a(Lm6/u0;Lb3/g;Ljava/util/List;Lpw0/a;Lay0/a;)Lm6/w;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

.method public static c(Ljava/io/File;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/io/File;->getParentFile()Ljava/io/File;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    invoke-virtual {p0}, Ljava/io/File;->exists()Z

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    if-eqz v0, :cond_2

    .line 13
    .line 14
    invoke-virtual {p0}, Ljava/io/File;->isDirectory()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_2

    .line 19
    .line 20
    invoke-virtual {p0}, Ljava/io/File;->getName()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    const-string v1, "firebaseSessions"

    .line 25
    .line 26
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    if-eqz v0, :cond_2

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/io/File;->delete()Z

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    if-eqz v0, :cond_1

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    new-instance v0, Ljava/io/IOException;

    .line 40
    .line 41
    new-instance v1, Ljava/lang/StringBuilder;

    .line 42
    .line 43
    const-string v2, "Failed to delete conflicting file: "

    .line 44
    .line 45
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-direct {v0, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw v0

    .line 59
    :cond_2
    :goto_0
    invoke-virtual {p0}, Ljava/io/File;->isDirectory()Z

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    if-eqz v0, :cond_3

    .line 64
    .line 65
    :goto_1
    return-void

    .line 66
    :cond_3
    :try_start_0
    invoke-virtual {p0}, Ljava/io/File;->toPath()Ljava/nio/file/Path;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    const/4 v1, 0x0

    .line 71
    new-array v1, v1, [Ljava/nio/file/attribute/FileAttribute;

    .line 72
    .line 73
    invoke-static {v0, v1}, Ljava/nio/file/Files;->createDirectories(Ljava/nio/file/Path;[Ljava/nio/file/attribute/FileAttribute;)Ljava/nio/file/Path;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 74
    .line 75
    .line 76
    return-void

    .line 77
    :catch_0
    move-exception v0

    .line 78
    new-instance v1, Ljava/io/IOException;

    .line 79
    .line 80
    new-instance v2, Ljava/lang/StringBuilder;

    .line 81
    .line 82
    const-string v3, "Failed to create directory: "

    .line 83
    .line 84
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    invoke-direct {v1, p0, v0}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 95
    .line 96
    .line 97
    throw v1
.end method


# virtual methods
.method public a(Lht/d;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lhu/t;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lhu/t;

    .line 7
    .line 8
    iget v1, v0, Lhu/t;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lhu/t;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhu/t;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lhu/t;-><init>(Lhu/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p0, v0, Lhu/t;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object p2, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lhu/t;->g:I

    .line 30
    .line 31
    const-string v2, "FirebaseSessions"

    .line 32
    .line 33
    const/4 v3, 0x2

    .line 34
    const/4 v4, 0x1

    .line 35
    const-string v5, ""

    .line 36
    .line 37
    if-eqz v1, :cond_3

    .line 38
    .line 39
    if-eq v1, v4, :cond_2

    .line 40
    .line 41
    if-ne v1, v3, :cond_1

    .line 42
    .line 43
    iget-object p1, v0, Lhu/t;->d:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p1, Ljava/lang/String;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 48
    .line 49
    .line 50
    goto :goto_5

    .line 51
    :catch_0
    move-exception p0

    .line 52
    goto/16 :goto_6

    .line 53
    .line 54
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 55
    .line 56
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 57
    .line 58
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw p0

    .line 62
    :cond_2
    iget-object p1, v0, Lhu/t;->d:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p1, Lht/d;

    .line 65
    .line 66
    :try_start_1
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :catch_1
    move-exception p0

    .line 71
    goto :goto_2

    .line 72
    :cond_3
    invoke-static {p0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    :try_start_2
    move-object p0, p1

    .line 76
    check-cast p0, Lht/c;

    .line 77
    .line 78
    invoke-virtual {p0}, Lht/c;->d()Laq/t;

    .line 79
    .line 80
    .line 81
    move-result-object p1
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 82
    :try_start_3
    const-string v1, "getToken(...)"

    .line 83
    .line 84
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    iput-object p0, v0, Lhu/t;->d:Ljava/lang/Object;

    .line 88
    .line 89
    iput v4, v0, Lhu/t;->g:I

    .line 90
    .line 91
    invoke-static {p1, v0}, Lkp/j8;->a(Laq/t;Lrx0/c;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p1
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_2

    .line 95
    if-ne p1, p2, :cond_4

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_4
    move-object v6, p1

    .line 99
    move-object p1, p0

    .line 100
    move-object p0, v6

    .line 101
    :goto_1
    :try_start_4
    check-cast p0, Lht/a;

    .line 102
    .line 103
    iget-object p0, p0, Lht/a;->a:Ljava/lang/String;
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_1

    .line 104
    .line 105
    move-object v6, p1

    .line 106
    move-object p1, p0

    .line 107
    move-object p0, v6

    .line 108
    goto :goto_3

    .line 109
    :catch_2
    move-exception p1

    .line 110
    move-object v6, p1

    .line 111
    move-object p1, p0

    .line 112
    move-object p0, v6

    .line 113
    :goto_2
    const-string v1, "Error getting authentication token."

    .line 114
    .line 115
    invoke-static {v2, v1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 116
    .line 117
    .line 118
    move-object p0, p1

    .line 119
    move-object p1, v5

    .line 120
    :goto_3
    :try_start_5
    check-cast p0, Lht/c;

    .line 121
    .line 122
    invoke-virtual {p0}, Lht/c;->c()Laq/t;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    const-string v1, "getId(...)"

    .line 127
    .line 128
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    iput-object p1, v0, Lhu/t;->d:Ljava/lang/Object;

    .line 132
    .line 133
    iput v3, v0, Lhu/t;->g:I

    .line 134
    .line 135
    invoke-static {p0, v0}, Lkp/j8;->a(Laq/t;Lrx0/c;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    if-ne p0, p2, :cond_5

    .line 140
    .line 141
    :goto_4
    return-object p2

    .line 142
    :cond_5
    :goto_5
    check-cast p0, Ljava/lang/String;
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_0

    .line 143
    .line 144
    if-nez p0, :cond_6

    .line 145
    .line 146
    goto :goto_7

    .line 147
    :cond_6
    move-object v5, p0

    .line 148
    goto :goto_7

    .line 149
    :goto_6
    const-string p2, "Error getting Firebase installation id ."

    .line 150
    .line 151
    invoke-static {v2, p2, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 152
    .line 153
    .line 154
    :goto_7
    new-instance p0, Lhu/u;

    .line 155
    .line 156
    invoke-direct {p0, v5, p1}, Lhu/u;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    return-object p0
.end method

.method public get()Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lhu/o;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p0, Lhu/b1;->a:Lhu/b1;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    sget-object p0, Lhu/a1;->a:Lhu/a1;

    .line 10
    .line 11
    return-object p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method
