.class public final La8/o;
.super Lt7/f0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:I

.field public final g:Ljava/lang/String;

.field public final h:I

.field public final i:Lt7/o;

.field public final j:I

.field public final k:Lh8/b0;

.field public final l:Z


# direct methods
.method public constructor <init>(ILjava/lang/Exception;I)V
    .locals 10

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v4, 0x0

    const/4 v5, -0x1

    const/4 v6, 0x0

    const/4 v7, 0x4

    move-object v0, p0

    move v1, p1

    move-object v2, p2

    move v3, p3

    .line 1
    invoke-direct/range {v0 .. v9}, La8/o;-><init>(ILjava/lang/Exception;ILjava/lang/String;ILt7/o;ILh8/b0;Z)V

    return-void
.end method

.method public constructor <init>(ILjava/lang/Exception;ILjava/lang/String;ILt7/o;ILh8/b0;Z)V
    .locals 13

    move/from16 v8, p7

    if-eqz p1, :cond_7

    const/4 v0, 0x3

    const/4 v1, 0x1

    if-eq p1, v1, :cond_1

    if-eq p1, v0, :cond_0

    .line 12
    const-string v0, "Unexpected runtime error"

    :goto_0
    move-object/from16 v5, p4

    move/from16 v6, p5

    move-object/from16 v7, p6

    goto :goto_2

    .line 13
    :cond_0
    const-string v0, "Remote error"

    goto :goto_0

    .line 14
    :cond_1
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    move-object/from16 v5, p4

    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " error, index="

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move/from16 v6, p5

    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v3, ", format="

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-object/from16 v7, p6

    invoke-virtual {v2, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v3, ", format_supported="

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 15
    sget-object v3, Lw7/w;->a:Ljava/lang/String;

    if-eqz v8, :cond_6

    if-eq v8, v1, :cond_5

    const/4 v1, 0x2

    if-eq v8, v1, :cond_4

    if-eq v8, v0, :cond_3

    const/4 v0, 0x4

    if-ne v8, v0, :cond_2

    .line 16
    const-string v0, "YES"

    goto :goto_1

    .line 17
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    throw p0

    .line 18
    :cond_3
    const-string v0, "NO_EXCEEDS_CAPABILITIES"

    goto :goto_1

    .line 19
    :cond_4
    const-string v0, "NO_UNSUPPORTED_DRM"

    goto :goto_1

    .line 20
    :cond_5
    const-string v0, "NO_UNSUPPORTED_TYPE"

    goto :goto_1

    .line 21
    :cond_6
    const-string v0, "NO"

    .line 22
    :goto_1
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    goto :goto_2

    :cond_7
    move-object/from16 v5, p4

    move/from16 v6, p5

    move-object/from16 v7, p6

    .line 23
    const-string v0, "Source error"

    :goto_2
    const/4 v1, 0x0

    .line 24
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-nez v1, :cond_8

    .line 25
    const-string v1, ": null"

    .line 26
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    :cond_8
    move-object v1, v0

    .line 27
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    move-result-wide v10

    move-object v0, p0

    move v4, p1

    move-object v2, p2

    move/from16 v3, p3

    move-object/from16 v9, p8

    move/from16 v12, p9

    .line 28
    invoke-direct/range {v0 .. v12}, La8/o;-><init>(Ljava/lang/String;Ljava/lang/Throwable;IILjava/lang/String;ILt7/o;ILh8/b0;JZ)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/Throwable;IILjava/lang/String;ILt7/o;ILh8/b0;JZ)V
    .locals 7

    move/from16 v6, p12

    .line 2
    sget-object v0, Landroid/os/Bundle;->EMPTY:Landroid/os/Bundle;

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move v3, p3

    move-wide/from16 v4, p10

    invoke-direct/range {v0 .. v5}, Lt7/f0;-><init>(Ljava/lang/String;Ljava/lang/Throwable;IJ)V

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v6, :cond_1

    if-ne p4, v2, :cond_0

    goto :goto_0

    :cond_0
    move v3, v1

    goto :goto_1

    :cond_1
    :goto_0
    move v3, v2

    .line 3
    :goto_1
    invoke-static {v3}, Lw7/a;->c(Z)V

    if-nez p2, :cond_2

    const/4 v3, 0x3

    if-ne p4, v3, :cond_3

    :cond_2
    move v1, v2

    .line 4
    :cond_3
    invoke-static {v1}, Lw7/a;->c(Z)V

    .line 5
    iput p4, p0, La8/o;->f:I

    .line 6
    iput-object p5, p0, La8/o;->g:Ljava/lang/String;

    .line 7
    iput p6, p0, La8/o;->h:I

    .line 8
    iput-object p7, p0, La8/o;->i:Lt7/o;

    move v1, p8

    .line 9
    iput v1, p0, La8/o;->j:I

    move-object/from16 v1, p9

    .line 10
    iput-object v1, p0, La8/o;->k:Lh8/b0;

    .line 11
    iput-boolean v6, p0, La8/o;->l:Z

    return-void
.end method


# virtual methods
.method public final a(Lh8/b0;)La8/o;
    .locals 13

    .line 1
    new-instance v0, La8/o;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    sget-object v2, Lw7/w;->a:Ljava/lang/String;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    iget-wide v10, p0, Lt7/f0;->e:J

    .line 14
    .line 15
    iget-boolean v12, p0, La8/o;->l:Z

    .line 16
    .line 17
    iget v3, p0, Lt7/f0;->d:I

    .line 18
    .line 19
    iget v4, p0, La8/o;->f:I

    .line 20
    .line 21
    iget-object v5, p0, La8/o;->g:Ljava/lang/String;

    .line 22
    .line 23
    iget v6, p0, La8/o;->h:I

    .line 24
    .line 25
    iget-object v7, p0, La8/o;->i:Lt7/o;

    .line 26
    .line 27
    iget v8, p0, La8/o;->j:I

    .line 28
    .line 29
    move-object v9, p1

    .line 30
    invoke-direct/range {v0 .. v12}, La8/o;-><init>(Ljava/lang/String;Ljava/lang/Throwable;IILjava/lang/String;ILt7/o;ILh8/b0;JZ)V

    .line 31
    .line 32
    .line 33
    return-object v0
.end method
