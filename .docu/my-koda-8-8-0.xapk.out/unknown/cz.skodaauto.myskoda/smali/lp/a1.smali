.class public abstract Llp/a1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Lh0/m;Ljava/util/ArrayList;)V
    .locals 1

    .line 1
    instance-of v0, p0, Lh0/n;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    check-cast p0, Lh0/n;

    .line 6
    .line 7
    iget-object p0, p0, Lh0/n;->a:Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lh0/m;

    .line 24
    .line 25
    invoke-static {v0, p1}, Llp/a1;->a(Lh0/m;Ljava/util/ArrayList;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    return-void

    .line 30
    :cond_1
    instance-of v0, p0, Lu/l0;

    .line 31
    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    check-cast p0, Lu/l0;

    .line 35
    .line 36
    iget-object p0, p0, Lu/l0;->a:Landroid/hardware/camera2/CameraCaptureSession$CaptureCallback;

    .line 37
    .line 38
    invoke-virtual {p1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_2
    new-instance v0, Lu/a0;

    .line 43
    .line 44
    invoke-direct {v0, p0}, Lu/a0;-><init>(Lh0/m;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    return-void
.end method

.method public static final b(Lhm0/a;)Lhm0/b;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lhm0/b;

    .line 4
    .line 5
    move-object v2, v1

    .line 6
    iget-object v1, v0, Lhm0/a;->a:Ljava/lang/String;

    .line 7
    .line 8
    move-object v3, v2

    .line 9
    iget-object v2, v0, Lhm0/a;->b:Ljava/lang/String;

    .line 10
    .line 11
    move-object v5, v3

    .line 12
    iget-wide v3, v0, Lhm0/a;->c:J

    .line 13
    .line 14
    move-object v6, v5

    .line 15
    iget-object v5, v0, Lhm0/a;->d:Ljava/lang/String;

    .line 16
    .line 17
    move-object v7, v6

    .line 18
    iget v6, v0, Lhm0/a;->e:I

    .line 19
    .line 20
    move-object v8, v7

    .line 21
    iget-object v7, v0, Lhm0/a;->f:Ljava/lang/String;

    .line 22
    .line 23
    move-object v9, v8

    .line 24
    iget-object v8, v0, Lhm0/a;->g:Ljava/lang/String;

    .line 25
    .line 26
    move-object v11, v9

    .line 27
    iget-wide v9, v0, Lhm0/a;->h:J

    .line 28
    .line 29
    move-object v12, v11

    .line 30
    iget-object v11, v0, Lhm0/a;->i:Ljava/lang/String;

    .line 31
    .line 32
    move-object v13, v12

    .line 33
    iget-object v12, v0, Lhm0/a;->j:Ljava/lang/String;

    .line 34
    .line 35
    move-object v14, v13

    .line 36
    iget-object v13, v0, Lhm0/a;->k:Ljava/lang/String;

    .line 37
    .line 38
    move-object v15, v14

    .line 39
    iget-object v14, v0, Lhm0/a;->l:Ljava/lang/String;

    .line 40
    .line 41
    move-object/from16 v16, v15

    .line 42
    .line 43
    iget-object v15, v0, Lhm0/a;->m:Ljava/lang/String;

    .line 44
    .line 45
    move-object/from16 v17, v1

    .line 46
    .line 47
    iget-object v1, v0, Lhm0/a;->n:Lhm0/d;

    .line 48
    .line 49
    move-object/from16 v18, v1

    .line 50
    .line 51
    iget-object v1, v0, Lhm0/a;->o:Ljava/lang/String;

    .line 52
    .line 53
    move-object/from16 v19, v1

    .line 54
    .line 55
    iget-wide v0, v0, Lhm0/a;->p:J

    .line 56
    .line 57
    const v21, 0x8000

    .line 58
    .line 59
    .line 60
    move-wide/from16 v22, v0

    .line 61
    .line 62
    move-object/from16 v1, v17

    .line 63
    .line 64
    move-object/from16 v17, v19

    .line 65
    .line 66
    move-wide/from16 v19, v22

    .line 67
    .line 68
    move-object/from16 v0, v16

    .line 69
    .line 70
    move-object/from16 v16, v18

    .line 71
    .line 72
    const/16 v18, 0x0

    .line 73
    .line 74
    invoke-direct/range {v0 .. v21}, Lhm0/b;-><init>(Ljava/lang/String;Ljava/lang/String;JLjava/lang/String;ILjava/lang/String;Ljava/lang/String;JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lhm0/d;Ljava/lang/String;Lhm0/c;JI)V

    .line 75
    .line 76
    .line 77
    return-object v0
.end method
