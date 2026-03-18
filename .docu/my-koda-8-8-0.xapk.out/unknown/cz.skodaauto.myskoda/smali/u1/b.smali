.class public abstract Lu1/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt40/a;

.field public static final b:Lu1/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lt40/a;

    .line 2
    .line 3
    const/16 v1, 0x1c

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lt40/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lu1/b;->a:Lt40/a;

    .line 9
    .line 10
    new-instance v0, Lu1/a;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lu1/b;->b:Lu1/a;

    .line 16
    .line 17
    return-void
.end method

.method public static final a(Lv1/a;Landroid/content/Context;ZLjava/lang/String;J)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-static/range {p4 .. p5}, Lg4/o0;->c(J)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_3

    .line 8
    .line 9
    invoke-virtual/range {p3 .. p3}, Ljava/lang/String;->length()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_0
    invoke-virtual/range {p1 .. p1}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    sget-object v2, Lu1/b;->a:Lt40/a;

    .line 21
    .line 22
    move-object/from16 v4, p1

    .line 23
    .line 24
    invoke-virtual {v2, v4}, Lt40/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    check-cast v2, Ljava/util/List;

    .line 29
    .line 30
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-eqz v3, :cond_1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    iget-object v3, v0, Lv1/a;->a:Landroidx/collection/l0;

    .line 38
    .line 39
    iget-object v0, v0, Lv1/a;->a:Landroidx/collection/l0;

    .line 40
    .line 41
    sget-object v10, Lw1/f;->b:Lw1/f;

    .line 42
    .line 43
    invoke-virtual {v3, v10}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    move-object v3, v2

    .line 47
    check-cast v3, Ljava/util/Collection;

    .line 48
    .line 49
    invoke-interface {v3}, Ljava/util/Collection;->size()I

    .line 50
    .line 51
    .line 52
    move-result v11

    .line 53
    const/4 v12, 0x0

    .line 54
    move v13, v12

    .line 55
    :goto_0
    if-ge v13, v11, :cond_2

    .line 56
    .line 57
    invoke-interface {v2, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v3

    .line 61
    move-object v5, v3

    .line 62
    check-cast v5, Landroid/content/pm/ResolveInfo;

    .line 63
    .line 64
    new-instance v14, Lw1/a;

    .line 65
    .line 66
    invoke-direct {v14, v13}, Lw1/a;-><init>(I)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v5, v1}, Landroid/content/pm/ResolveInfo;->loadLabel(Landroid/content/pm/PackageManager;)Ljava/lang/CharSequence;

    .line 70
    .line 71
    .line 72
    move-result-object v3

    .line 73
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v15

    .line 77
    new-instance v3, Lu1/c;

    .line 78
    .line 79
    move/from16 v6, p2

    .line 80
    .line 81
    move-object/from16 v7, p3

    .line 82
    .line 83
    move-wide/from16 v8, p4

    .line 84
    .line 85
    invoke-direct/range {v3 .. v9}, Lu1/c;-><init>(Landroid/content/Context;Landroid/content/pm/ResolveInfo;ZLjava/lang/String;J)V

    .line 86
    .line 87
    .line 88
    new-instance v4, Lw1/d;

    .line 89
    .line 90
    invoke-direct {v4, v14, v15, v12, v3}, Lw1/d;-><init>(Ljava/lang/Object;Ljava/lang/String;ILay0/k;)V

    .line 91
    .line 92
    .line 93
    invoke-virtual {v0, v4}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    add-int/lit8 v13, v13, 0x1

    .line 97
    .line 98
    move-object/from16 v4, p1

    .line 99
    .line 100
    goto :goto_0

    .line 101
    :cond_2
    invoke-virtual {v0, v10}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 102
    .line 103
    .line 104
    :cond_3
    :goto_1
    return-void
.end method
