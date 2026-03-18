.class public final Landroidx/lifecycle/c1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llx0/i;
.implements Lg4/s;
.implements Lju/b;
.implements Ll9/d;
.implements Ltn/b;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Ljava/lang/Object;

.field public h:Ljava/lang/Object;

.field public i:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 3

    const/16 v0, 0x16

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 164
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 165
    new-instance v0, Ld21/a;

    .line 166
    sget-object v1, Ld21/b;->h:Ld21/b;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Ld21/a;-><init>(Ld21/b;I)V

    .line 167
    iput-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 168
    new-instance v0, Lb81/b;

    invoke-direct {v0, p0}, Lb81/b;-><init>(Landroidx/lifecycle/c1;)V

    iput-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 169
    new-instance v0, Li21/b;

    invoke-direct {v0, p0}, Li21/b;-><init>(Landroidx/lifecycle/c1;)V

    iput-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 170
    new-instance v0, Lgw0/c;

    invoke-direct {v0, p0}, Lgw0/c;-><init>(Landroidx/lifecycle/c1;)V

    iput-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 171
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 172
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 173
    new-instance v0, Li21/a;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Li21/a;-><init>(I)V

    iput-object v0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    .line 1
    iput p1, p0, Landroidx/lifecycle/c1;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(La7/j;)V
    .locals 0

    const/16 p1, 0x17

    iput p1, p0, Landroidx/lifecycle/c1;->d:I

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 p1, 0x0

    .line 15
    iput-object p1, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 16
    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 17
    iput-object p1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 18
    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 19
    iput-object p1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/SharedPreferences;Ljava/util/concurrent/ScheduledThreadPoolExecutor;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 188
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 189
    new-instance v0, Ljava/util/ArrayDeque;

    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 190
    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 191
    const-string p1, "topic_operation_queue"

    iput-object p1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 192
    const-string p1, ","

    iput-object p1, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 193
    iput-object p2, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/graphics/drawable/Drawable$Callback;)V
    .locals 3

    const/16 v0, 0x19

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    new-instance v0, Lvp/y1;

    const/4 v1, 0x1

    const/4 v2, 0x0

    .line 28
    invoke-direct {v0, v1, v2}, Lvp/y1;-><init>(IZ)V

    .line 29
    iput-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 30
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 31
    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 32
    const-string v0, ".ttf"

    iput-object v0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 33
    instance-of v0, p1, Landroid/view/View;

    if-nez v0, :cond_0

    .line 34
    const-string p1, "LottieDrawable must be inside of a view for images to work."

    invoke-static {p1}, Lgn/c;->a(Ljava/lang/String;)V

    const/4 p1, 0x0

    .line 35
    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    goto :goto_0

    .line 36
    :cond_0
    check-cast p1, Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object p1

    invoke-virtual {p1}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    move-result-object p1

    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    :goto_0
    return-void
.end method

.method public constructor <init>(Landroid/text/Layout;)V
    .locals 5

    const/16 v0, 0x8

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 38
    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    const/4 v0, 0x0

    move v1, v0

    .line 39
    :cond_0
    iget-object v2, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    check-cast v2, Landroid/text/Layout;

    invoke-virtual {v2}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    move-result-object v2

    const/16 v3, 0xa

    const/4 v4, 0x4

    invoke-static {v2, v3, v1, v4}, Lly0/p;->J(Ljava/lang/CharSequence;CII)I

    move-result v1

    if-gez v1, :cond_1

    .line 40
    iget-object v1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    check-cast v1, Landroid/text/Layout;

    invoke-virtual {v1}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    move-result-object v1

    invoke-interface {v1}, Ljava/lang/CharSequence;->length()I

    move-result v1

    goto :goto_0

    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 41
    :goto_0
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 42
    iget-object v2, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    check-cast v2, Landroid/text/Layout;

    invoke-virtual {v2}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    move-result-object v2

    invoke-interface {v2}, Ljava/lang/CharSequence;->length()I

    move-result v2

    if-lt v1, v2, :cond_0

    .line 43
    iput-object p1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 44
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p1

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1, p1}, Ljava/util/ArrayList;-><init>(I)V

    :goto_1
    if-ge v0, p1, :cond_2

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v0, v0, 0x1

    goto :goto_1

    :cond_2
    iput-object v1, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 45
    iget-object p1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    check-cast p1, Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p1

    new-array p1, p1, [Z

    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 46
    iget-object p0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    check-cast p0, Ljava/util/ArrayList;

    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    return-void
.end method

.method public constructor <init>(Le81/x;Ll71/w;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    const-string v0, "dependencies"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 12
    iput-object p2, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 13
    new-instance p1, La2/e;

    const/16 p2, 0xa

    invoke-direct {p1, p0, p2}, La2/e;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lg01/c;)V
    .locals 1

    const/16 v0, 0xd

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    const-string v0, "taskRunner"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 223
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 224
    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 225
    sget-object p1, Lk01/n;->a:Lk01/m;

    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 226
    sget-object p1, Lk01/c;->a:Lk01/c;

    iput-object p1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lg4/g;Lg4/p0;Ljava/util/List;Lt4/c;Lk4/m;)V
    .locals 30

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    const/4 v3, 0x6

    iput v3, v0, Landroidx/lifecycle/c1;->d:I

    .line 63
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 64
    iput-object v1, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    move-object/from16 v3, p3

    .line 65
    iput-object v3, v0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 66
    sget-object v3, Llx0/j;->f:Llx0/j;

    new-instance v4, Lg4/p;

    const/4 v5, 0x0

    invoke-direct {v4, v0, v5}, Lg4/p;-><init>(Landroidx/lifecycle/c1;I)V

    invoke-static {v3, v4}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object v4

    iput-object v4, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 67
    new-instance v4, Lg4/p;

    const/4 v6, 0x1

    invoke-direct {v4, v0, v6}, Lg4/p;-><init>(Landroidx/lifecycle/c1;I)V

    invoke-static {v3, v4}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    move-result-object v3

    iput-object v3, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 68
    iget-object v3, v2, Lg4/p0;->b:Lg4/t;

    .line 69
    sget-object v4, Lg4/h;->a:Lg4/g;

    .line 70
    iget-object v4, v1, Lg4/g;->g:Ljava/util/ArrayList;

    iget-object v7, v1, Lg4/g;->e:Ljava/lang/String;

    .line 71
    sget-object v8, Lmx0/s;->d:Lmx0/s;

    if-eqz v4, :cond_0

    .line 72
    new-instance v9, Lg4/f;

    .line 73
    invoke-direct {v9, v6}, Lg4/f;-><init>(I)V

    .line 74
    invoke-static {v4, v9}, Lmx0/q;->p0(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object v4

    goto :goto_0

    :cond_0
    move-object v4, v8

    .line 75
    :goto_0
    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    .line 76
    new-instance v9, Lmx0/l;

    invoke-direct {v9}, Lmx0/l;-><init>()V

    .line 77
    move-object v10, v4

    check-cast v10, Ljava/util/Collection;

    invoke-interface {v10}, Ljava/util/Collection;->size()I

    move-result v10

    move v11, v5

    move v12, v11

    :goto_1
    if-ge v11, v10, :cond_9

    .line 78
    invoke-interface {v4, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v13

    .line 79
    check-cast v13, Lg4/e;

    .line 80
    iget-object v14, v13, Lg4/e;->a:Ljava/lang/Object;

    .line 81
    check-cast v14, Lg4/t;

    invoke-virtual {v3, v14}, Lg4/t;->a(Lg4/t;)Lg4/t;

    move-result-object v14

    const/16 v15, 0xe

    invoke-static {v13, v14, v5, v15}, Lg4/e;->a(Lg4/e;Lg4/b;II)Lg4/e;

    move-result-object v13

    iget-object v14, v13, Lg4/e;->a:Ljava/lang/Object;

    iget v15, v13, Lg4/e;->c:I

    iget v13, v13, Lg4/e;->b:I

    :goto_2
    if-ge v12, v13, :cond_3

    .line 82
    invoke-virtual {v9}, Lmx0/l;->isEmpty()Z

    move-result v16

    if-nez v16, :cond_3

    .line 83
    invoke-virtual {v9}, Lmx0/l;->last()Ljava/lang/Object;

    move-result-object v16

    move-object/from16 v5, v16

    check-cast v5, Lg4/e;

    move-object/from16 v16, v4

    .line 84
    iget v4, v5, Lg4/e;->c:I

    move-object/from16 v17, v8

    iget-object v8, v5, Lg4/e;->a:Ljava/lang/Object;

    if-ge v13, v4, :cond_1

    .line 85
    new-instance v4, Lg4/e;

    invoke-direct {v4, v8, v12, v13}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v12, v13

    move-object/from16 v4, v16

    move-object/from16 v8, v17

    :goto_3
    const/4 v5, 0x0

    goto :goto_2

    :cond_1
    move/from16 v18, v10

    .line 86
    new-instance v10, Lg4/e;

    invoke-direct {v10, v8, v12, v4}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 87
    iget v12, v5, Lg4/e;->c:I

    .line 88
    :goto_4
    invoke-virtual {v9}, Lmx0/l;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_2

    invoke-virtual {v9}, Lmx0/l;->last()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lg4/e;

    .line 89
    iget v4, v4, Lg4/e;->c:I

    if-ne v12, v4, :cond_2

    .line 90
    invoke-virtual {v9}, Lmx0/l;->removeLast()Ljava/lang/Object;

    goto :goto_4

    :cond_2
    move-object/from16 v4, v16

    move-object/from16 v8, v17

    move/from16 v10, v18

    goto :goto_3

    :cond_3
    move-object/from16 v16, v4

    move-object/from16 v17, v8

    move/from16 v18, v10

    if-ge v12, v13, :cond_4

    .line 91
    new-instance v4, Lg4/e;

    invoke-direct {v4, v3, v12, v13}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v12, v13

    .line 92
    :cond_4
    invoke-virtual {v9}, Lmx0/l;->n()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lg4/e;

    if-eqz v4, :cond_8

    .line 93
    iget v5, v4, Lg4/e;->c:I

    iget-object v8, v4, Lg4/e;->a:Ljava/lang/Object;

    .line 94
    iget v4, v4, Lg4/e;->b:I

    if-ne v4, v13, :cond_5

    if-ne v5, v15, :cond_5

    .line 95
    invoke-virtual {v9}, Lmx0/l;->removeLast()Ljava/lang/Object;

    .line 96
    new-instance v4, Lg4/e;

    check-cast v8, Lg4/t;

    check-cast v14, Lg4/t;

    invoke-virtual {v8, v14}, Lg4/t;->a(Lg4/t;)Lg4/t;

    move-result-object v5

    invoke-direct {v4, v5, v13, v15}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    .line 97
    invoke-virtual {v9, v4}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    goto :goto_5

    :cond_5
    if-ne v4, v5, :cond_6

    .line 98
    new-instance v10, Lg4/e;

    invoke-direct {v10, v8, v4, v5}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    invoke-virtual {v6, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 99
    invoke-virtual {v9}, Lmx0/l;->removeLast()Ljava/lang/Object;

    .line 100
    new-instance v4, Lg4/e;

    invoke-direct {v4, v14, v13, v15}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    .line 101
    invoke-virtual {v9, v4}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    goto :goto_5

    :cond_6
    if-lt v5, v15, :cond_7

    .line 102
    new-instance v4, Lg4/e;

    check-cast v8, Lg4/t;

    check-cast v14, Lg4/t;

    invoke-virtual {v8, v14}, Lg4/t;->a(Lg4/t;)Lg4/t;

    move-result-object v5

    invoke-direct {v4, v5, v13, v15}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    .line 103
    invoke-virtual {v9, v4}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    goto :goto_5

    .line 104
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0}, Ljava/lang/IllegalArgumentException;-><init>()V

    throw v0

    .line 105
    :cond_8
    new-instance v4, Lg4/e;

    invoke-direct {v4, v14, v13, v15}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    .line 106
    invoke-virtual {v9, v4}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    :goto_5
    add-int/lit8 v11, v11, 0x1

    move-object/from16 v4, v16

    move-object/from16 v8, v17

    move/from16 v10, v18

    const/4 v5, 0x0

    goto/16 :goto_1

    :cond_9
    move-object/from16 v17, v8

    .line 107
    :goto_6
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    move-result v4

    if-gt v12, v4, :cond_b

    invoke-virtual {v9}, Lmx0/l;->isEmpty()Z

    move-result v4

    if-nez v4, :cond_b

    .line 108
    invoke-virtual {v9}, Lmx0/l;->last()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lg4/e;

    .line 109
    new-instance v5, Lg4/e;

    .line 110
    iget-object v8, v4, Lg4/e;->a:Ljava/lang/Object;

    iget v4, v4, Lg4/e;->c:I

    .line 111
    invoke-direct {v5, v8, v12, v4}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    invoke-virtual {v6, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 112
    :goto_7
    invoke-virtual {v9}, Lmx0/l;->isEmpty()Z

    move-result v5

    if-nez v5, :cond_a

    invoke-virtual {v9}, Lmx0/l;->last()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lg4/e;

    .line 113
    iget v5, v5, Lg4/e;->c:I

    if-ne v4, v5, :cond_a

    .line 114
    invoke-virtual {v9}, Lmx0/l;->removeLast()Ljava/lang/Object;

    goto :goto_7

    :cond_a
    move v12, v4

    goto :goto_6

    .line 115
    :cond_b
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    move-result v4

    if-ge v12, v4, :cond_c

    .line 116
    new-instance v4, Lg4/e;

    invoke-virtual {v7}, Ljava/lang/String;->length()I

    move-result v5

    invoke-direct {v4, v3, v12, v5}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 117
    :cond_c
    invoke-virtual {v6}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_d

    .line 118
    new-instance v4, Lg4/e;

    const/4 v5, 0x0

    invoke-direct {v4, v3, v5, v5}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    invoke-virtual {v6, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_8

    :cond_d
    const/4 v5, 0x0

    .line 119
    :goto_8
    new-instance v4, Ljava/util/ArrayList;

    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v8

    invoke-direct {v4, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 120
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    move-result v8

    move v9, v5

    :goto_9
    if-ge v9, v8, :cond_15

    .line 121
    invoke-virtual {v6, v9}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    .line 122
    check-cast v10, Lg4/e;

    .line 123
    iget v11, v10, Lg4/e;->b:I

    iget v12, v10, Lg4/e;->c:I

    .line 124
    new-instance v13, Lg4/g;

    if-eq v11, v12, :cond_e

    .line 125
    invoke-virtual {v7, v11, v12}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v14

    const-string v15, "substring(...)"

    invoke-static {v14, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    goto :goto_a

    :cond_e
    const-string v14, ""

    .line 126
    :goto_a
    new-instance v15, Lfw0/i0;

    const/16 v5, 0xb

    invoke-direct {v15, v5}, Lfw0/i0;-><init>(I)V

    invoke-static {v1, v11, v12, v15}, Lg4/h;->a(Lg4/g;IILfw0/i0;)Ljava/util/List;

    move-result-object v5

    if-nez v5, :cond_f

    move-object/from16 v5, v17

    .line 127
    :cond_f
    invoke-direct {v13, v14, v5}, Lg4/g;-><init>(Ljava/lang/String;Ljava/util/List;)V

    .line 128
    iget-object v5, v10, Lg4/e;->a:Ljava/lang/Object;

    .line 129
    check-cast v5, Lg4/t;

    .line 130
    iget v10, v5, Lg4/t;->b:I

    const/high16 v15, -0x80000000

    if-ne v10, v15, :cond_10

    .line 131
    iget v10, v3, Lg4/t;->b:I

    .line 132
    iget v15, v5, Lg4/t;->a:I

    move-object/from16 v29, v6

    move-object/from16 v16, v7

    .line 133
    iget-wide v6, v5, Lg4/t;->c:J

    .line 134
    iget-object v1, v5, Lg4/t;->d:Lr4/q;

    move-object/from16 v23, v1

    .line 135
    iget-object v1, v5, Lg4/t;->e:Lg4/w;

    move-object/from16 v24, v1

    .line 136
    iget-object v1, v5, Lg4/t;->f:Lr4/i;

    move-object/from16 v25, v1

    .line 137
    iget v1, v5, Lg4/t;->g:I

    move/from16 v26, v1

    .line 138
    iget v1, v5, Lg4/t;->h:I

    .line 139
    iget-object v5, v5, Lg4/t;->i:Lr4/s;

    .line 140
    new-instance v18, Lg4/t;

    move/from16 v27, v1

    move-object/from16 v28, v5

    move-wide/from16 v21, v6

    move/from16 v20, v10

    move/from16 v19, v15

    invoke-direct/range {v18 .. v28}, Lg4/t;-><init>(IIJLr4/q;Lg4/w;Lr4/i;IILr4/s;)V

    move-object/from16 v5, v18

    goto :goto_b

    :cond_10
    move-object/from16 v29, v6

    move-object/from16 v16, v7

    .line 141
    :goto_b
    new-instance v1, Lg4/r;

    .line 142
    new-instance v6, Lg4/p0;

    .line 143
    iget-object v7, v2, Lg4/p0;->a:Lg4/g0;

    .line 144
    invoke-virtual {v3, v5}, Lg4/t;->a(Lg4/t;)Lg4/t;

    move-result-object v5

    .line 145
    invoke-direct {v6, v7, v5}, Lg4/p0;-><init>(Lg4/g0;Lg4/t;)V

    .line 146
    iget-object v5, v13, Lg4/g;->d:Ljava/util/List;

    if-nez v5, :cond_11

    move-object/from16 v21, v17

    goto :goto_c

    :cond_11
    move-object/from16 v21, v5

    .line 147
    :goto_c
    iget-object v5, v0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    check-cast v5, Ljava/util/List;

    .line 148
    new-instance v7, Ljava/util/ArrayList;

    invoke-interface {v5}, Ljava/util/List;->size()I

    move-result v10

    invoke-direct {v7, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 149
    move-object v10, v5

    check-cast v10, Ljava/util/Collection;

    invoke-interface {v10}, Ljava/util/Collection;->size()I

    move-result v10

    const/4 v13, 0x0

    :goto_d
    if-ge v13, v10, :cond_14

    .line 150
    invoke-interface {v5, v13}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v15

    .line 151
    check-cast v15, Lg4/e;

    .line 152
    iget v2, v15, Lg4/e;->b:I

    move-object/from16 v25, v3

    iget v3, v15, Lg4/e;->c:I

    .line 153
    invoke-static {v11, v12, v2, v3}, Lg4/h;->b(IIII)Z

    move-result v18

    if-eqz v18, :cond_13

    if-gt v11, v2, :cond_12

    if-gt v3, v12, :cond_12

    :goto_e
    move/from16 v18, v2

    goto :goto_f

    .line 154
    :cond_12
    const-string v18, "placeholder can not overlap with paragraph."

    .line 155
    invoke-static/range {v18 .. v18}, Lm4/a;->a(Ljava/lang/String;)V

    goto :goto_e

    .line 156
    :goto_f
    new-instance v2, Lg4/e;

    .line 157
    iget-object v15, v15, Lg4/e;->a:Ljava/lang/Object;

    move/from16 v19, v3

    sub-int v3, v18, v11

    move-object/from16 v18, v5

    sub-int v5, v19, v11

    .line 158
    invoke-direct {v2, v15, v3, v5}, Lg4/e;-><init>(Ljava/lang/Object;II)V

    .line 159
    invoke-virtual {v7, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_10

    :cond_13
    move-object/from16 v18, v5

    :goto_10
    add-int/lit8 v13, v13, 0x1

    move-object/from16 v2, p2

    move-object/from16 v5, v18

    move-object/from16 v3, v25

    goto :goto_d

    :cond_14
    move-object/from16 v25, v3

    .line 160
    new-instance v18, Lo4/c;

    move-object/from16 v24, p4

    move-object/from16 v23, p5

    move-object/from16 v20, v6

    move-object/from16 v22, v7

    move-object/from16 v19, v14

    invoke-direct/range {v18 .. v24}, Lo4/c;-><init>(Ljava/lang/String;Lg4/p0;Ljava/util/List;Ljava/util/List;Lk4/m;Lt4/c;)V

    move-object/from16 v2, v18

    .line 161
    invoke-direct {v1, v2, v11, v12}, Lg4/r;-><init>(Lo4/c;II)V

    .line 162
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v9, v9, 0x1

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    move-object/from16 v7, v16

    move-object/from16 v6, v29

    const/4 v5, 0x0

    goto/16 :goto_9

    .line 163
    :cond_15
    iput-object v4, v0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh0/b0;Lh0/b0;Lp0/m;)V
    .locals 1

    const/16 v0, 0x12

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 200
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 201
    iput-object p1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 202
    iput-object p2, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 203
    iput-object p3, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lhu/q;)V
    .locals 2

    const/16 v0, 0xe

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 194
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 195
    new-instance v0, La5/e;

    const/16 v1, 0x1e

    invoke-direct {v0, v1}, La5/e;-><init>(I)V

    iput-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 196
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 197
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 198
    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 199
    new-instance p1, Lhu/q;

    const/16 v0, 0xa

    invoke-direct {p1, p0, v0}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lhy0/d;Lq61/n;Lay0/a;Lq61/n;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    const-string v0, "viewModelClass"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 47
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 48
    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 49
    iput-object p2, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 50
    iput-object p3, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 51
    iput-object p4, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/io/File;Ljava/io/File;)V
    .locals 2

    const/16 v0, 0x15

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 3
    new-instance v0, Lb81/c;

    const/16 v1, 0x1c

    invoke-direct {v0, v1}, Lb81/c;-><init>(I)V

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 6
    iput-object p2, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 7
    iput-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 8
    new-instance p1, Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    invoke-direct {p1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;-><init>()V

    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 9
    new-instance p1, Llx0/l;

    const/4 p2, 0x0

    invoke-direct {p1, p2, p2}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    iput-object p1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p6, p0, Landroidx/lifecycle/c1;->d:I

    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    iput-object p2, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    iput-object p3, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    iput-object p4, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    iput-object p5, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/util/Map;)V
    .locals 1

    const/16 v0, 0x11

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    const-string v0, "initialState"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 21
    invoke-static {p1}, Lmx0/x;->w(Ljava/util/Map;)Ljava/util/LinkedHashMap;

    move-result-object p1

    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 22
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 23
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 24
    new-instance p1, Ljava/util/LinkedHashMap;

    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 25
    new-instance p1, Lb/i;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Lb/i;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lr9/c;Ljava/util/HashMap;Ljava/util/HashMap;Ljava/util/HashMap;)V
    .locals 2

    const/16 v0, 0x13

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 52
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 53
    iput-object p1, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 54
    iput-object p3, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 55
    iput-object p4, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 56
    invoke-static {p2}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    move-result-object p2

    iput-object p2, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 57
    new-instance p2, Ljava/util/TreeSet;

    invoke-direct {p2}, Ljava/util/TreeSet;-><init>()V

    const/4 p3, 0x0

    .line 58
    invoke-virtual {p1, p2, p3}, Lr9/c;->d(Ljava/util/TreeSet;Z)V

    .line 59
    invoke-virtual {p2}, Ljava/util/TreeSet;->size()I

    move-result p1

    new-array p1, p1, [J

    .line 60
    invoke-virtual {p2}, Ljava/util/TreeSet;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result p4

    if-eqz p4, :cond_0

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Ljava/lang/Long;

    invoke-virtual {p4}, Ljava/lang/Long;->longValue()J

    move-result-wide v0

    add-int/lit8 p4, p3, 0x1

    .line 61
    aput-wide v0, p1, p3

    move p3, p4

    goto :goto_0

    .line 62
    :cond_0
    iput-object p1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lsr/f;)V
    .locals 3

    const/4 v0, 0x1

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 204
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 205
    iget-object v0, p1, Lsr/f;->a:Landroid/content/Context;

    .line 206
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 207
    iget-object v1, p1, Lsr/f;->c:Lsr/i;

    .line 208
    const-class v2, Las/d;

    invoke-virtual {p1, v2}, Lsr/f;->b(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Las/d;

    .line 209
    iget-object p1, p1, Las/d;->b:Lgt/b;

    .line 210
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 211
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 212
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 213
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 214
    iput-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 215
    iget-object v0, v1, Lsr/i;->a:Ljava/lang/String;

    .line 216
    iput-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 217
    iget-object v0, v1, Lsr/i;->b:Ljava/lang/String;

    .line 218
    iput-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 219
    iget-object v0, v1, Lsr/i;->g:Ljava/lang/String;

    .line 220
    iput-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    if-eqz v0, :cond_0

    .line 221
    iput-object p1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    return-void

    .line 222
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "FirebaseOptions#getProjectId cannot be null."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Lz9/y;)V
    .locals 4

    const/16 v0, 0x18

    iput v0, p0, Landroidx/lifecycle/c1;->d:I

    const-string v0, "navController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    iget-object v0, p1, Lz9/y;->a:Landroid/content/Context;

    .line 175
    const-string v1, "context"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 176
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 177
    new-instance v1, Lca/d;

    const/4 v2, 0x0

    invoke-direct {v1, v0, v2}, Lca/d;-><init>(Landroid/content/Context;Z)V

    iput-object v1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 178
    new-instance v1, Lz70/e0;

    const/4 v2, 0x5

    invoke-direct {v1, v2}, Lz70/e0;-><init>(I)V

    invoke-static {v0, v1}, Lky0/l;->k(Ljava/lang/Object;Lay0/k;)Lky0/j;

    move-result-object v1

    new-instance v2, Lz70/e0;

    const/4 v3, 0x6

    invoke-direct {v2, v3}, Lz70/e0;-><init>(I)V

    .line 179
    invoke-static {v1, v2}, Lky0/l;->o(Lky0/j;Lay0/k;)Lky0/g;

    move-result-object v1

    .line 180
    invoke-static {v1}, Lky0/l;->g(Lky0/g;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/app/Activity;

    if-eqz v1, :cond_0

    .line 181
    new-instance v2, Landroid/content/Intent;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-direct {v2, v0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V

    goto :goto_0

    .line 182
    :cond_0
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object v1

    invoke-virtual {v0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Landroid/content/pm/PackageManager;->getLaunchIntentForPackage(Ljava/lang/String;)Landroid/content/Intent;

    move-result-object v2

    if-nez v2, :cond_1

    .line 183
    new-instance v2, Landroid/content/Intent;

    invoke-direct {v2}, Landroid/content/Intent;-><init>()V

    :cond_1
    :goto_0
    const v0, 0x10008000

    .line 184
    invoke-virtual {v2, v0}, Landroid/content/Intent;->addFlags(I)Landroid/content/Intent;

    iput-object v2, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 185
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 186
    iget-object p1, p1, Lz9/y;->b:Lca/g;

    invoke-virtual {p1}, Lca/g;->i()Lz9/v;

    move-result-object p1

    .line 187
    iput-object p1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    return-void
.end method

.method public static final d(Landroidx/lifecycle/c1;Ljava/io/File;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, Lww/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lww/f;

    .line 7
    .line 8
    iget v1, v0, Lww/f;->i:I

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
    iput v1, v0, Lww/f;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lww/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lww/f;-><init>(Landroidx/lifecycle/c1;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lww/f;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lww/f;->i:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-wide p0, v0, Lww/f;->f:J

    .line 37
    .line 38
    iget-object v1, v0, Lww/f;->e:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    iget-object v0, v0, Lww/f;->d:Lkotlin/jvm/internal/f0;

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto/16 :goto_2

    .line 46
    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    new-instance p2, Lkotlin/jvm/internal/f0;

    .line 59
    .line 60
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 61
    .line 62
    .line 63
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 64
    .line 65
    .line 66
    move-result-wide v4

    .line 67
    new-instance v2, La4/b;

    .line 68
    .line 69
    const/16 v6, 0xc

    .line 70
    .line 71
    invoke-direct {v2, v6, p0, p1}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    iput-object p2, v0, Lww/f;->d:Lkotlin/jvm/internal/f0;

    .line 75
    .line 76
    iput-object p2, v0, Lww/f;->e:Lkotlin/jvm/internal/f0;

    .line 77
    .line 78
    iput-wide v4, v0, Lww/f;->f:J

    .line 79
    .line 80
    iput v3, v0, Lww/f;->i:I

    .line 81
    .line 82
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    sget-object p1, Lvy0/x;->d:Lvy0/w;

    .line 87
    .line 88
    invoke-interface {p0, p1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    check-cast p0, Lvy0/x;

    .line 93
    .line 94
    if-nez p0, :cond_3

    .line 95
    .line 96
    sget-object p0, Lvy0/p0;->a:Lcz0/e;

    .line 97
    .line 98
    sget-object p0, Lcz0/d;->e:Lcz0/d;

    .line 99
    .line 100
    :cond_3
    new-instance p1, Lvy0/l;

    .line 101
    .line 102
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    invoke-direct {p1, v3, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p1}, Lvy0/l;->q()V

    .line 110
    .line 111
    .line 112
    new-instance v0, Ljava/util/concurrent/FutureTask;

    .line 113
    .line 114
    new-instance v3, Lcq/s1;

    .line 115
    .line 116
    const/4 v6, 0x2

    .line 117
    invoke-direct {v3, v6, v2, p1}, Lcq/s1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    invoke-direct {v0, v3}, Ljava/util/concurrent/FutureTask;-><init>(Ljava/util/concurrent/Callable;)V

    .line 121
    .line 122
    .line 123
    new-instance v2, La3/f;

    .line 124
    .line 125
    const/16 v3, 0x1b

    .line 126
    .line 127
    invoke-direct {v2, v0, v3}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1, v2}, Lvy0/l;->s(Lay0/k;)V

    .line 131
    .line 132
    .line 133
    instance-of v2, p0, Lvy0/a1;

    .line 134
    .line 135
    if-eqz v2, :cond_4

    .line 136
    .line 137
    move-object v2, p0

    .line 138
    check-cast v2, Lvy0/a1;

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_4
    const/4 v2, 0x0

    .line 142
    :goto_1
    if-eqz v2, :cond_5

    .line 143
    .line 144
    invoke-virtual {v2}, Lvy0/a1;->e0()Ljava/util/concurrent/Executor;

    .line 145
    .line 146
    .line 147
    move-result-object v2

    .line 148
    if-nez v2, :cond_6

    .line 149
    .line 150
    :cond_5
    new-instance v2, Lvy0/o0;

    .line 151
    .line 152
    invoke-direct {v2, p0}, Lvy0/o0;-><init>(Lvy0/x;)V

    .line 153
    .line 154
    .line 155
    :cond_6
    invoke-interface {v2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {p1}, Lvy0/l;->p()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    if-ne p0, v1, :cond_7

    .line 163
    .line 164
    return-object v1

    .line 165
    :cond_7
    move-object v0, p2

    .line 166
    move-object v1, v0

    .line 167
    move-object p2, p0

    .line 168
    move-wide p0, v4

    .line 169
    :goto_2
    iput-object p2, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 170
    .line 171
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 172
    .line 173
    .line 174
    move-result-wide v1

    .line 175
    sub-long/2addr v1, p0

    .line 176
    long-to-float p0, v1

    .line 177
    const/high16 p1, 0x447a0000    # 1000.0f

    .line 178
    .line 179
    div-float/2addr p0, p1

    .line 180
    new-instance p1, Ljava/lang/StringBuilder;

    .line 181
    .line 182
    const-string p2, "Parsed cached Translations in "

    .line 183
    .line 184
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 185
    .line 186
    .line 187
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 188
    .line 189
    .line 190
    const/16 p0, 0x73

    .line 191
    .line 192
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 196
    .line 197
    .line 198
    move-result-object p0

    .line 199
    invoke-static {p0}, Let/d;->c(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    iget-object p0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 203
    .line 204
    return-object p0
.end method

.method public static o(Landroid/content/SharedPreferences;Ljava/util/concurrent/ScheduledThreadPoolExecutor;)Landroidx/lifecycle/c1;
    .locals 5

    .line 1
    new-instance v0, Landroidx/lifecycle/c1;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Landroidx/lifecycle/c1;-><init>(Landroid/content/SharedPreferences;Ljava/util/concurrent/ScheduledThreadPoolExecutor;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/ArrayDeque;

    .line 9
    .line 10
    monitor-enter p0

    .line 11
    :try_start_0
    iget-object p1, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p1, Ljava/util/ArrayDeque;

    .line 14
    .line 15
    invoke-virtual {p1}, Ljava/util/ArrayDeque;->clear()V

    .line 16
    .line 17
    .line 18
    iget-object p1, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p1, Landroid/content/SharedPreferences;

    .line 21
    .line 22
    iget-object v1, v0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Ljava/lang/String;

    .line 25
    .line 26
    const-string v2, ""

    .line 27
    .line 28
    invoke-interface {p1, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-nez v1, :cond_4

    .line 37
    .line 38
    iget-object v1, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 39
    .line 40
    check-cast v1, Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {p1, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-nez v1, :cond_0

    .line 47
    .line 48
    goto :goto_2

    .line 49
    :cond_0
    iget-object v1, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v1, Ljava/lang/String;

    .line 52
    .line 53
    const/4 v2, -0x1

    .line 54
    invoke-virtual {p1, v1, v2}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    array-length v1, p1

    .line 59
    if-nez v1, :cond_1

    .line 60
    .line 61
    const-string v1, "FirebaseMessaging"

    .line 62
    .line 63
    const-string v2, "Corrupted queue. Please check the queue contents and item separator provided"

    .line 64
    .line 65
    invoke-static {v1, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :catchall_0
    move-exception p1

    .line 70
    goto :goto_3

    .line 71
    :cond_1
    :goto_0
    array-length v1, p1

    .line 72
    const/4 v2, 0x0

    .line 73
    :goto_1
    if-ge v2, v1, :cond_3

    .line 74
    .line 75
    aget-object v3, p1, v2

    .line 76
    .line 77
    invoke-static {v3}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 78
    .line 79
    .line 80
    move-result v4

    .line 81
    if-nez v4, :cond_2

    .line 82
    .line 83
    iget-object v4, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v4, Ljava/util/ArrayDeque;

    .line 86
    .line 87
    invoke-virtual {v4, v3}, Ljava/util/ArrayDeque;->add(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    :cond_2
    add-int/lit8 v2, v2, 0x1

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_3
    monitor-exit p0

    .line 94
    return-object v0

    .line 95
    :cond_4
    :goto_2
    monitor-exit p0

    .line 96
    return-object v0

    .line 97
    :goto_3
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 98
    throw p1
.end method


# virtual methods
.method public A()Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-lez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public B(II)I
    .locals 2

    .line 1
    :goto_0
    if-le p1, p2, :cond_3

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v0, Landroid/text/Layout;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    add-int/lit8 v1, p1, -0x1

    .line 12
    .line 13
    invoke-interface {v0, v1}, Ljava/lang/CharSequence;->charAt(I)C

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/16 v1, 0x20

    .line 18
    .line 19
    if-eq v0, v1, :cond_2

    .line 20
    .line 21
    const/16 v1, 0xa

    .line 22
    .line 23
    if-eq v0, v1, :cond_2

    .line 24
    .line 25
    const/16 v1, 0x1680

    .line 26
    .line 27
    if-eq v0, v1, :cond_2

    .line 28
    .line 29
    const/16 v1, 0x2000

    .line 30
    .line 31
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    if-ltz v1, :cond_0

    .line 36
    .line 37
    const/16 v1, 0x200a

    .line 38
    .line 39
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->g(II)I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-gtz v1, :cond_0

    .line 44
    .line 45
    const/16 v1, 0x2007

    .line 46
    .line 47
    if-ne v0, v1, :cond_2

    .line 48
    .line 49
    :cond_0
    const/16 v1, 0x205f

    .line 50
    .line 51
    if-eq v0, v1, :cond_2

    .line 52
    .line 53
    const/16 v1, 0x3000

    .line 54
    .line 55
    if-ne v0, v1, :cond_1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_1
    return p1

    .line 59
    :cond_2
    :goto_1
    add-int/lit8 p1, p1, -0x1

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_3
    return p1
.end method

.method public C(Ljava/util/List;Z)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    const-string v1, "modules"

    .line 4
    .line 5
    move-object/from16 v2, p1

    .line 6
    .line 7
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static {v2}, Lkp/x;->a(Ljava/util/List;)Ljava/util/LinkedHashSet;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    iget-object v2, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lgw0/c;

    .line 17
    .line 18
    iget-object v3, v2, Lgw0/c;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v3, Ljava/util/concurrent/ConcurrentHashMap;

    .line 21
    .line 22
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    :goto_0
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    if-eqz v5, :cond_7

    .line 31
    .line 32
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v5

    .line 36
    check-cast v5, Le21/a;

    .line 37
    .line 38
    iget-object v6, v5, Le21/a;->c:Ljava/util/LinkedHashMap;

    .line 39
    .line 40
    invoke-virtual {v6}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 41
    .line 42
    .line 43
    move-result-object v6

    .line 44
    invoke-interface {v6}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    :goto_1
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v7

    .line 52
    if-eqz v7, :cond_5

    .line 53
    .line 54
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v7

    .line 58
    check-cast v7, Ljava/util/Map$Entry;

    .line 59
    .line 60
    invoke-interface {v7}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v8

    .line 64
    check-cast v8, Ljava/lang/String;

    .line 65
    .line 66
    invoke-interface {v7}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v7

    .line 70
    check-cast v7, Lc21/b;

    .line 71
    .line 72
    iget-object v9, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v9, Landroidx/lifecycle/c1;

    .line 75
    .line 76
    const-string v10, "mapping"

    .line 77
    .line 78
    invoke-static {v8, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    const-string v10, "factory"

    .line 82
    .line 83
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    iget-object v10, v7, Lc21/b;->a:La21/a;

    .line 87
    .line 88
    iget-object v11, v2, Lgw0/c;->f:Ljava/lang/Object;

    .line 89
    .line 90
    check-cast v11, Ljava/util/concurrent/ConcurrentHashMap;

    .line 91
    .line 92
    invoke-virtual {v11, v8}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v12

    .line 96
    check-cast v12, Lc21/b;

    .line 97
    .line 98
    const-string v14, "\' -> \'"

    .line 99
    .line 100
    if-eqz v12, :cond_3

    .line 101
    .line 102
    const-string v12, "msg"

    .line 103
    .line 104
    if-eqz p2, :cond_2

    .line 105
    .line 106
    iget-object v15, v9, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 107
    .line 108
    check-cast v15, Lap0/o;

    .line 109
    .line 110
    new-instance v13, Ljava/lang/StringBuilder;

    .line 111
    .line 112
    move-object/from16 v16, v1

    .line 113
    .line 114
    const-string v1, "(+) override index \'"

    .line 115
    .line 116
    invoke-direct {v13, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v13, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 120
    .line 121
    .line 122
    invoke-virtual {v13, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v13, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    const/16 v1, 0x27

    .line 129
    .line 130
    invoke-virtual {v13, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 134
    .line 135
    .line 136
    move-result-object v1

    .line 137
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 138
    .line 139
    .line 140
    invoke-static {v1, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    sget-object v12, Ld21/b;->f:Ld21/b;

    .line 144
    .line 145
    invoke-virtual {v15, v12, v1}, Lap0/o;->N(Ld21/b;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v3}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 149
    .line 150
    .line 151
    move-result-object v1

    .line 152
    check-cast v1, Ljava/lang/Iterable;

    .line 153
    .line 154
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 159
    .line 160
    .line 161
    move-result v12

    .line 162
    if-eqz v12, :cond_1

    .line 163
    .line 164
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v12

    .line 168
    move-object v13, v12

    .line 169
    check-cast v13, Lc21/d;

    .line 170
    .line 171
    iget-object v13, v13, Lc21/b;->a:La21/a;

    .line 172
    .line 173
    invoke-virtual {v13, v10}, La21/a;->equals(Ljava/lang/Object;)Z

    .line 174
    .line 175
    .line 176
    move-result v13

    .line 177
    if-eqz v13, :cond_0

    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_1
    const/4 v12, 0x0

    .line 181
    :goto_2
    check-cast v12, Lc21/d;

    .line 182
    .line 183
    if-eqz v12, :cond_4

    .line 184
    .line 185
    invoke-virtual {v10}, La21/a;->hashCode()I

    .line 186
    .line 187
    .line 188
    move-result v1

    .line 189
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-virtual {v3, v1}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    goto :goto_3

    .line 197
    :cond_2
    new-instance v0, Lb0/l;

    .line 198
    .line 199
    new-instance v1, Ljava/lang/StringBuilder;

    .line 200
    .line 201
    const-string v2, "Already existing definition for "

    .line 202
    .line 203
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    invoke-virtual {v1, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 207
    .line 208
    .line 209
    const-string v2, " at "

    .line 210
    .line 211
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object v1

    .line 221
    invoke-static {v1, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    throw v0

    .line 228
    :cond_3
    move-object/from16 v16, v1

    .line 229
    .line 230
    :cond_4
    :goto_3
    iget-object v1, v9, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v1, Lap0/o;

    .line 233
    .line 234
    new-instance v9, Ljava/lang/StringBuilder;

    .line 235
    .line 236
    const-string v12, "(+) index \'"

    .line 237
    .line 238
    invoke-direct {v9, v12}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 239
    .line 240
    .line 241
    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    invoke-virtual {v9, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 245
    .line 246
    .line 247
    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 248
    .line 249
    .line 250
    const/16 v10, 0x27

    .line 251
    .line 252
    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 253
    .line 254
    .line 255
    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 256
    .line 257
    .line 258
    move-result-object v9

    .line 259
    invoke-virtual {v1, v9}, Lap0/o;->u(Ljava/lang/String;)V

    .line 260
    .line 261
    .line 262
    invoke-virtual {v11, v8, v7}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 263
    .line 264
    .line 265
    move-object/from16 v1, v16

    .line 266
    .line 267
    goto/16 :goto_1

    .line 268
    .line 269
    :cond_5
    move-object/from16 v16, v1

    .line 270
    .line 271
    iget-object v1, v5, Le21/a;->b:Ljava/util/LinkedHashSet;

    .line 272
    .line 273
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 274
    .line 275
    .line 276
    move-result-object v1

    .line 277
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 278
    .line 279
    .line 280
    move-result v5

    .line 281
    if-eqz v5, :cond_6

    .line 282
    .line 283
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 284
    .line 285
    .line 286
    move-result-object v5

    .line 287
    check-cast v5, Lc21/d;

    .line 288
    .line 289
    iget-object v6, v5, Lc21/b;->a:La21/a;

    .line 290
    .line 291
    invoke-virtual {v6}, La21/a;->hashCode()I

    .line 292
    .line 293
    .line 294
    move-result v6

    .line 295
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 296
    .line 297
    .line 298
    move-result-object v6

    .line 299
    invoke-virtual {v3, v6, v5}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 300
    .line 301
    .line 302
    goto :goto_4

    .line 303
    :cond_6
    move-object/from16 v1, v16

    .line 304
    .line 305
    goto/16 :goto_0

    .line 306
    .line 307
    :cond_7
    move-object/from16 v16, v1

    .line 308
    .line 309
    iget-object v0, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v0, Li21/b;

    .line 312
    .line 313
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 314
    .line 315
    .line 316
    invoke-interface/range {v16 .. v16}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 317
    .line 318
    .line 319
    move-result-object v1

    .line 320
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 321
    .line 322
    .line 323
    move-result v2

    .line 324
    if-eqz v2, :cond_8

    .line 325
    .line 326
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object v2

    .line 330
    check-cast v2, Le21/a;

    .line 331
    .line 332
    iget-object v3, v0, Li21/b;->b:Ljava/util/Set;

    .line 333
    .line 334
    iget-object v2, v2, Le21/a;->d:Ljava/util/LinkedHashSet;

    .line 335
    .line 336
    invoke-interface {v3, v2}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 337
    .line 338
    .line 339
    goto :goto_5

    .line 340
    :cond_8
    return-void
.end method

.method public D(Ljava/net/URL;[BLas/e;Z)Ljava/lang/String;
    .locals 8

    .line 1
    invoke-virtual {p1}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    check-cast p1, Ljava/net/HttpURLConnection;

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    :try_start_0
    invoke-virtual {p1, v0}, Ljava/net/URLConnection;->setDoOutput(Z)V

    .line 9
    .line 10
    .line 11
    array-length v1, p2

    .line 12
    invoke-virtual {p1, v1}, Ljava/net/HttpURLConnection;->setFixedLengthStreamingMode(I)V

    .line 13
    .line 14
    .line 15
    const-string v1, "Content-Type"

    .line 16
    .line 17
    const-string v2, "application/json"

    .line 18
    .line 19
    invoke-virtual {p1, v1, v2}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object v1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v1, Lgt/b;

    .line 25
    .line 26
    invoke-interface {v1}, Lgt/b;->get()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Let/e;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    .line 32
    const/4 v2, 0x0

    .line 33
    const/4 v3, 0x0

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    :try_start_1
    check-cast v1, Let/c;

    .line 37
    .line 38
    iget-object v4, v1, Let/c;->b:Landroid/content/Context;

    .line 39
    .line 40
    invoke-static {v4}, Llp/yf;->a(Landroid/content/Context;)Z

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    if-nez v4, :cond_0

    .line 45
    .line 46
    const-string v1, ""

    .line 47
    .line 48
    invoke-static {v1}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    goto :goto_0

    .line 53
    :cond_0
    iget-object v4, v1, Let/c;->e:Ljava/util/concurrent/Executor;

    .line 54
    .line 55
    new-instance v5, Let/b;

    .line 56
    .line 57
    invoke-direct {v5, v1, v2}, Let/b;-><init>(Let/c;I)V

    .line 58
    .line 59
    .line 60
    invoke-static {v4, v5}, Ljp/l1;->c(Ljava/util/concurrent/Executor;Ljava/util/concurrent/Callable;)Laq/t;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    :goto_0
    invoke-static {v1}, Ljp/l1;->a(Laq/j;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    check-cast v1, Ljava/lang/String;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 69
    .line 70
    move-object v3, v1

    .line 71
    goto :goto_1

    .line 72
    :catch_0
    :try_start_2
    const-string v1, "androidx.lifecycle.c1"

    .line 73
    .line 74
    const-string v4, "Unable to get heartbeats!"

    .line 75
    .line 76
    invoke-static {v1, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 77
    .line 78
    .line 79
    :cond_1
    :goto_1
    if-eqz v3, :cond_2

    .line 80
    .line 81
    const-string v1, "X-Firebase-Client"

    .line 82
    .line 83
    invoke-virtual {p1, v1, v3}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    goto :goto_2

    .line 87
    :catchall_0
    move-exception p0

    .line 88
    goto/16 :goto_c

    .line 89
    .line 90
    :cond_2
    :goto_2
    const-string v1, "X-Android-Package"

    .line 91
    .line 92
    iget-object v3, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 93
    .line 94
    check-cast v3, Landroid/content/Context;

    .line 95
    .line 96
    invoke-virtual {v3}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    invoke-virtual {p1, v1, v3}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    const-string v1, "X-Android-Cert"

    .line 104
    .line 105
    invoke-virtual {p0}, Landroidx/lifecycle/c1;->w()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-virtual {p1, v1, p0}, Ljava/net/URLConnection;->setRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    new-instance p0, Ljava/io/BufferedOutputStream;

    .line 113
    .line 114
    invoke-virtual {p1}, Ljava/net/URLConnection;->getOutputStream()Ljava/io/OutputStream;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    array-length v3, p2

    .line 119
    invoke-direct {p0, v1, v3}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;I)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 120
    .line 121
    .line 122
    :try_start_3
    array-length v1, p2

    .line 123
    invoke-virtual {p0, p2, v2, v1}, Ljava/io/OutputStream;->write([BII)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    .line 124
    .line 125
    .line 126
    :try_start_4
    invoke-virtual {p0}, Ljava/io/OutputStream;->close()V

    .line 127
    .line 128
    .line 129
    invoke-virtual {p1}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 130
    .line 131
    .line 132
    move-result p0

    .line 133
    const/16 p2, 0x12c

    .line 134
    .line 135
    const/16 v1, 0xc8

    .line 136
    .line 137
    if-lt p0, v1, :cond_3

    .line 138
    .line 139
    if-ge p0, p2, :cond_3

    .line 140
    .line 141
    move v3, v0

    .line 142
    goto :goto_3

    .line 143
    :cond_3
    move v3, v2

    .line 144
    :goto_3
    if-eqz v3, :cond_4

    .line 145
    .line 146
    invoke-virtual {p1}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 147
    .line 148
    .line 149
    move-result-object v3

    .line 150
    goto :goto_4

    .line 151
    :cond_4
    invoke-virtual {p1}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 152
    .line 153
    .line 154
    move-result-object v3

    .line 155
    :goto_4
    new-instance v4, Ljava/lang/StringBuilder;

    .line 156
    .line 157
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    .line 158
    .line 159
    .line 160
    new-instance v5, Ljava/io/BufferedReader;

    .line 161
    .line 162
    new-instance v6, Ljava/io/InputStreamReader;

    .line 163
    .line 164
    sget-object v7, Ljava/nio/charset/StandardCharsets;->UTF_8:Ljava/nio/charset/Charset;

    .line 165
    .line 166
    invoke-direct {v6, v3, v7}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    .line 167
    .line 168
    .line 169
    invoke-direct {v5, v6}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 170
    .line 171
    .line 172
    :goto_5
    :try_start_5
    invoke-virtual {v5}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v3

    .line 176
    if-eqz v3, :cond_5

    .line 177
    .line 178
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 179
    .line 180
    .line 181
    goto :goto_5

    .line 182
    :catchall_1
    move-exception p0

    .line 183
    goto/16 :goto_9

    .line 184
    .line 185
    :cond_5
    :try_start_6
    invoke-virtual {v5}, Ljava/io/BufferedReader;->close()V

    .line 186
    .line 187
    .line 188
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 189
    .line 190
    .line 191
    move-result-object v3

    .line 192
    if-lt p0, v1, :cond_6

    .line 193
    .line 194
    if-ge p0, p2, :cond_6

    .line 195
    .line 196
    goto :goto_6

    .line 197
    :cond_6
    move v0, v2

    .line 198
    :goto_6
    if-nez v0, :cond_9

    .line 199
    .line 200
    iget-object p2, p3, Las/e;->c:Ljava/lang/Object;

    .line 201
    .line 202
    iget-wide v0, p3, Las/e;->a:J

    .line 203
    .line 204
    const-wide/16 v4, 0x1

    .line 205
    .line 206
    add-long/2addr v0, v4

    .line 207
    iput-wide v0, p3, Las/e;->a:J

    .line 208
    .line 209
    const/16 p2, 0x190

    .line 210
    .line 211
    if-eq p0, p2, :cond_8

    .line 212
    .line 213
    const/16 p2, 0x194

    .line 214
    .line 215
    if-ne p0, p2, :cond_7

    .line 216
    .line 217
    goto :goto_7

    .line 218
    :cond_7
    invoke-static {}, Ljava/lang/Math;->random()D

    .line 219
    .line 220
    .line 221
    move-result-wide v0

    .line 222
    const-wide/high16 v4, 0x3fe0000000000000L    # 0.5

    .line 223
    .line 224
    mul-double/2addr v0, v4

    .line 225
    const-wide/high16 v4, 0x3ff0000000000000L    # 1.0

    .line 226
    .line 227
    add-double/2addr v0, v4

    .line 228
    iget-wide v4, p3, Las/e;->a:J

    .line 229
    .line 230
    long-to-double v4, v4

    .line 231
    mul-double/2addr v4, v0

    .line 232
    const-wide/high16 v0, 0x4000000000000000L    # 2.0

    .line 233
    .line 234
    invoke-static {v0, v1, v4, v5}, Ljava/lang/Math;->pow(DD)D

    .line 235
    .line 236
    .line 237
    move-result-wide v0

    .line 238
    const-wide v4, 0x408f400000000000L    # 1000.0

    .line 239
    .line 240
    .line 241
    .line 242
    .line 243
    mul-double/2addr v0, v4

    .line 244
    double-to-long v0, v0

    .line 245
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 246
    .line 247
    .line 248
    move-result-wide v4

    .line 249
    const-wide/32 v6, 0xdbba00

    .line 250
    .line 251
    .line 252
    invoke-static {v0, v1, v6, v7}, Ljava/lang/Math;->min(JJ)J

    .line 253
    .line 254
    .line 255
    move-result-wide v0

    .line 256
    add-long/2addr v0, v4

    .line 257
    iput-wide v0, p3, Las/e;->b:J

    .line 258
    .line 259
    goto :goto_8

    .line 260
    :cond_8
    :goto_7
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 261
    .line 262
    .line 263
    move-result-wide v0

    .line 264
    const-wide/32 v4, 0x5265c00

    .line 265
    .line 266
    .line 267
    add-long/2addr v0, v4

    .line 268
    iput-wide v0, p3, Las/e;->b:J

    .line 269
    .line 270
    :goto_8
    new-instance p0, Lorg/json/JSONObject;

    .line 271
    .line 272
    invoke-direct {p0, v3}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 273
    .line 274
    .line 275
    const-string p2, "error"

    .line 276
    .line 277
    invoke-virtual {p0, p2}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object p0

    .line 281
    new-instance p2, Lorg/json/JSONObject;

    .line 282
    .line 283
    invoke-direct {p2, p0}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 284
    .line 285
    .line 286
    const-string p0, "code"

    .line 287
    .line 288
    invoke-virtual {p2, p0}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    .line 289
    .line 290
    .line 291
    move-result p0

    .line 292
    const-string p3, "message"

    .line 293
    .line 294
    invoke-virtual {p2, p3}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    .line 295
    .line 296
    .line 297
    move-result-object p2

    .line 298
    new-instance p3, Lsr/h;

    .line 299
    .line 300
    new-instance p4, Ljava/lang/StringBuilder;

    .line 301
    .line 302
    invoke-direct {p4}, Ljava/lang/StringBuilder;-><init>()V

    .line 303
    .line 304
    .line 305
    const-string v0, "Error returned from API. code: "

    .line 306
    .line 307
    invoke-virtual {p4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 308
    .line 309
    .line 310
    invoke-virtual {p4, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 311
    .line 312
    .line 313
    const-string p0, " body: "

    .line 314
    .line 315
    invoke-virtual {p4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 316
    .line 317
    .line 318
    invoke-virtual {p4, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 319
    .line 320
    .line 321
    invoke-virtual {p4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 322
    .line 323
    .line 324
    move-result-object p0

    .line 325
    invoke-direct {p3, p0}, Lsr/h;-><init>(Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    throw p3

    .line 329
    :cond_9
    if-eqz p4, :cond_a

    .line 330
    .line 331
    const-wide/16 v0, 0x0

    .line 332
    .line 333
    iput-wide v0, p3, Las/e;->a:J

    .line 334
    .line 335
    const-wide/16 v0, -0x1

    .line 336
    .line 337
    iput-wide v0, p3, Las/e;->b:J
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 338
    .line 339
    :cond_a
    invoke-virtual {p1}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 340
    .line 341
    .line 342
    return-object v3

    .line 343
    :goto_9
    :try_start_7
    invoke-virtual {v5}, Ljava/io/BufferedReader;->close()V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_2

    .line 344
    .line 345
    .line 346
    goto :goto_a

    .line 347
    :catchall_2
    move-exception p2

    .line 348
    :try_start_8
    invoke-virtual {p0, p2}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 349
    .line 350
    .line 351
    :goto_a
    throw p0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_0

    .line 352
    :catchall_3
    move-exception p2

    .line 353
    :try_start_9
    invoke-virtual {p0}, Ljava/io/OutputStream;->close()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 354
    .line 355
    .line 356
    goto :goto_b

    .line 357
    :catchall_4
    move-exception p0

    .line 358
    :try_start_a
    invoke-virtual {p2, p0}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 359
    .line 360
    .line 361
    :goto_b
    throw p2
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_0

    .line 362
    :goto_c
    invoke-virtual {p1}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 363
    .line 364
    .line 365
    throw p0
.end method

.method public E(III)Lka/a;
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, La5/e;

    .line 4
    .line 5
    invoke-virtual {p0}, La5/e;->a()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lka/a;

    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    new-instance p0, Lka/a;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    iput p1, p0, Lka/a;->a:I

    .line 19
    .line 20
    iput p2, p0, Lka/a;->b:I

    .line 21
    .line 22
    iput p3, p0, Lka/a;->c:I

    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    iput p1, p0, Lka/a;->a:I

    .line 26
    .line 27
    iput p2, p0, Lka/a;->b:I

    .line 28
    .line 29
    iput p3, p0, Lka/a;->c:I

    .line 30
    .line 31
    return-object p0
.end method

.method public F(Lka/a;)V
    .locals 3

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lhu/q;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    iget p0, p1, Lka/a;->a:I

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    if-eq p0, v1, :cond_3

    .line 16
    .line 17
    const/4 v2, 0x2

    .line 18
    if-eq p0, v2, :cond_2

    .line 19
    .line 20
    const/4 v1, 0x4

    .line 21
    if-eq p0, v1, :cond_1

    .line 22
    .line 23
    const/16 v1, 0x8

    .line 24
    .line 25
    if-ne p0, v1, :cond_0

    .line 26
    .line 27
    iget p0, p1, Lka/a;->b:I

    .line 28
    .line 29
    iget p1, p1, Lka/a;->c:I

    .line 30
    .line 31
    invoke-virtual {v0, p0, p1}, Lhu/q;->L(II)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 36
    .line 37
    new-instance v0, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    const-string v1, "Unknown update op type for "

    .line 40
    .line 41
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p1

    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_1
    iget p0, p1, Lka/a;->b:I

    .line 56
    .line 57
    iget p1, p1, Lka/a;->c:I

    .line 58
    .line 59
    invoke-virtual {v0, p0, p1}, Lhu/q;->H(II)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_2
    iget p0, p1, Lka/a;->b:I

    .line 64
    .line 65
    iget p1, p1, Lka/a;->c:I

    .line 66
    .line 67
    iget-object v0, v0, Lhu/q;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    .line 70
    .line 71
    const/4 v2, 0x0

    .line 72
    invoke-virtual {v0, p0, p1, v2}, Landroidx/recyclerview/widget/RecyclerView;->P(IIZ)V

    .line 73
    .line 74
    .line 75
    iput-boolean v1, v0, Landroidx/recyclerview/widget/RecyclerView;->t1:Z

    .line 76
    .line 77
    return-void

    .line 78
    :cond_3
    iget p0, p1, Lka/a;->b:I

    .line 79
    .line 80
    iget p1, p1, Lka/a;->c:I

    .line 81
    .line 82
    invoke-virtual {v0, p0, p1}, Lhu/q;->K(II)V

    .line 83
    .line 84
    .line 85
    return-void
.end method

.method public G(Luw/b;Ljava/io/InputStream;)V
    .locals 9

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/io/File;

    .line 4
    .line 5
    const-string v1, "tmp-locale-"

    .line 6
    .line 7
    const-string v2, ".xml"

    .line 8
    .line 9
    invoke-static {v1, v2, v0}, Ljava/io/File;->createTempFile(Ljava/lang/String;Ljava/lang/String;Ljava/io/File;)Ljava/io/File;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v1, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v3, "Downloading Translations to File: "

    .line 16
    .line 17
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/io/File;->getAbsoluteFile()Ljava/io/File;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-static {v1}, Let/d;->c(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :try_start_0
    new-instance v1, Ljava/io/FileOutputStream;

    .line 35
    .line 36
    invoke-direct {v1, v0}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    .line 37
    .line 38
    .line 39
    new-instance v3, Ljava/io/BufferedOutputStream;

    .line 40
    .line 41
    const/16 v4, 0x2000

    .line 42
    .line 43
    invoke-direct {v3, v1, v4}, Ljava/io/BufferedOutputStream;-><init>(Ljava/io/OutputStream;I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 44
    .line 45
    .line 46
    :try_start_1
    invoke-virtual {p2}, Ljava/io/InputStream;->read()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    :goto_0
    if-ltz v1, :cond_0

    .line 51
    .line 52
    invoke-virtual {v3, v1}, Ljava/io/OutputStream;->write(I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/io/InputStream;->read()I

    .line 56
    .line 57
    .line 58
    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_3

    .line 59
    goto :goto_0

    .line 60
    :cond_0
    :try_start_2
    invoke-interface {v3}, Ljava/io/Closeable;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 61
    .line 62
    .line 63
    :try_start_3
    invoke-interface {p2}, Ljava/io/Closeable;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 64
    .line 65
    .line 66
    iget-object p2, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p2, Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 69
    .line 70
    invoke-virtual {p2}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->readLock()Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;

    .line 71
    .line 72
    .line 73
    move-result-object v1

    .line 74
    invoke-virtual {p2}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->getWriteHoldCount()I

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    const/4 v4, 0x0

    .line 79
    if-nez v3, :cond_1

    .line 80
    .line 81
    invoke-virtual {p2}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->getReadHoldCount()I

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    goto :goto_1

    .line 86
    :cond_1
    move v3, v4

    .line 87
    :goto_1
    move v5, v4

    .line 88
    :goto_2
    if-ge v5, v3, :cond_2

    .line 89
    .line 90
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;->unlock()V

    .line 91
    .line 92
    .line 93
    add-int/lit8 v5, v5, 0x1

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_2
    invoke-virtual {p2}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->writeLock()Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;

    .line 97
    .line 98
    .line 99
    move-result-object p2

    .line 100
    invoke-virtual {p2}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;->lock()V

    .line 101
    .line 102
    .line 103
    :try_start_4
    invoke-virtual {p1}, Luw/b;->b()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v5

    .line 107
    new-instance v6, Ljava/io/File;

    .line 108
    .line 109
    iget-object v7, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 110
    .line 111
    check-cast v7, Ljava/io/File;

    .line 112
    .line 113
    new-instance v8, Ljava/lang/StringBuilder;

    .line 114
    .line 115
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v8, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v8, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object v2

    .line 128
    invoke-direct {v6, v7, v2}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    new-instance v2, Ljava/lang/StringBuilder;

    .line 132
    .line 133
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 134
    .line 135
    .line 136
    const-string v5, "Writing Translations to Locale Cache: "

    .line 137
    .line 138
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 139
    .line 140
    .line 141
    invoke-virtual {v6}, Ljava/io/File;->getAbsoluteFile()Ljava/io/File;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 146
    .line 147
    .line 148
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v2

    .line 152
    invoke-static {v2}, Let/d;->c(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v0, v6}, Ljava/io/File;->renameTo(Ljava/io/File;)Z

    .line 156
    .line 157
    .line 158
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 159
    .line 160
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    .line 161
    .line 162
    new-instance v2, Lww/g;

    .line 163
    .line 164
    const/4 v5, 0x0

    .line 165
    invoke-direct {v2, p1, p0, v5}, Lww/g;-><init>(Luw/b;Landroidx/lifecycle/c1;Lkotlin/coroutines/Continuation;)V

    .line 166
    .line 167
    .line 168
    invoke-static {v0, v2}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 169
    .line 170
    .line 171
    :goto_3
    if-ge v4, v3, :cond_3

    .line 172
    .line 173
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;->lock()V

    .line 174
    .line 175
    .line 176
    add-int/lit8 v4, v4, 0x1

    .line 177
    .line 178
    goto :goto_3

    .line 179
    :cond_3
    invoke-virtual {p2}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;->unlock()V

    .line 180
    .line 181
    .line 182
    return-void

    .line 183
    :catchall_0
    move-exception p0

    .line 184
    :goto_4
    if-ge v4, v3, :cond_4

    .line 185
    .line 186
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;->lock()V

    .line 187
    .line 188
    .line 189
    add-int/lit8 v4, v4, 0x1

    .line 190
    .line 191
    goto :goto_4

    .line 192
    :cond_4
    invoke-virtual {p2}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$WriteLock;->unlock()V

    .line 193
    .line 194
    .line 195
    throw p0

    .line 196
    :catchall_1
    move-exception p0

    .line 197
    goto :goto_6

    .line 198
    :catchall_2
    move-exception p0

    .line 199
    goto :goto_5

    .line 200
    :catchall_3
    move-exception p0

    .line 201
    :try_start_5
    throw p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    .line 202
    :catchall_4
    move-exception p1

    .line 203
    :try_start_6
    invoke-static {v3, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 204
    .line 205
    .line 206
    throw p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 207
    :goto_5
    :try_start_7
    throw p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    .line 208
    :catchall_5
    move-exception p1

    .line 209
    :try_start_8
    invoke-static {p2, p0}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 210
    .line 211
    .line 212
    throw p1
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 213
    :goto_6
    invoke-virtual {v0}, Ljava/io/File;->exists()Z

    .line 214
    .line 215
    .line 216
    move-result p1

    .line 217
    if-eqz p1, :cond_5

    .line 218
    .line 219
    new-instance p1, Ljava/lang/StringBuilder;

    .line 220
    .line 221
    const-string p2, "Deleting File: "

    .line 222
    .line 223
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {v0}, Ljava/io/File;->getAbsoluteFile()Ljava/io/File;

    .line 227
    .line 228
    .line 229
    move-result-object p2

    .line 230
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 231
    .line 232
    .line 233
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 234
    .line 235
    .line 236
    move-result-object p1

    .line 237
    const/4 p2, 0x5

    .line 238
    invoke-static {p2, p1, p0}, Let/d;->g(ILjava/lang/String;Ljava/lang/Throwable;)V

    .line 239
    .line 240
    .line 241
    :try_start_9
    invoke-virtual {v0}, Ljava/io/File;->delete()Z
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_6

    .line 242
    .line 243
    .line 244
    goto :goto_7

    .line 245
    :catchall_6
    move-exception p1

    .line 246
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 247
    .line 248
    .line 249
    :cond_5
    :goto_7
    throw p0
.end method

.method public H(Ljava/util/ArrayList;)V
    .locals 4

    .line 1
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    check-cast v2, Lka/a;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    iget-object v3, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v3, La5/e;

    .line 20
    .line 21
    invoke-virtual {v3, v2}, La5/e;->c(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    add-int/lit8 v1, v1, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    invoke-virtual {p1}, Ljava/util/ArrayList;->clear()V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public I(Ljava/lang/Object;Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "key"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Ljava/util/LinkedHashMap;

    .line 9
    .line 10
    invoke-interface {v0, p2, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v0, Ljava/util/LinkedHashMap;

    .line 16
    .line 17
    invoke-virtual {v0, p2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lyy0/j1;

    .line 22
    .line 23
    if-eqz v0, :cond_0

    .line 24
    .line 25
    check-cast v0, Lyy0/c2;

    .line 26
    .line 27
    invoke-virtual {v0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    :cond_0
    iget-object p0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 33
    .line 34
    invoke-virtual {p0, p2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Lyy0/j1;

    .line 39
    .line 40
    if-eqz p0, :cond_1

    .line 41
    .line 42
    check-cast p0, Lyy0/c2;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    :cond_1
    return-void
.end method

.method public J(II)I
    .locals 9

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, La5/e;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    const/4 v2, 0x1

    .line 14
    sub-int/2addr v1, v2

    .line 15
    :goto_0
    const/16 v3, 0x8

    .line 16
    .line 17
    if-ltz v1, :cond_d

    .line 18
    .line 19
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    check-cast v4, Lka/a;

    .line 24
    .line 25
    iget v5, v4, Lka/a;->a:I

    .line 26
    .line 27
    const/4 v6, 0x2

    .line 28
    if-ne v5, v3, :cond_8

    .line 29
    .line 30
    iget v3, v4, Lka/a;->b:I

    .line 31
    .line 32
    iget v5, v4, Lka/a;->c:I

    .line 33
    .line 34
    if-ge v3, v5, :cond_0

    .line 35
    .line 36
    move v7, v3

    .line 37
    move v8, v5

    .line 38
    goto :goto_1

    .line 39
    :cond_0
    move v8, v3

    .line 40
    move v7, v5

    .line 41
    :goto_1
    if-lt p1, v7, :cond_6

    .line 42
    .line 43
    if-gt p1, v8, :cond_6

    .line 44
    .line 45
    if-ne v7, v3, :cond_3

    .line 46
    .line 47
    if-ne p2, v2, :cond_1

    .line 48
    .line 49
    add-int/lit8 v5, v5, 0x1

    .line 50
    .line 51
    iput v5, v4, Lka/a;->c:I

    .line 52
    .line 53
    goto :goto_2

    .line 54
    :cond_1
    if-ne p2, v6, :cond_2

    .line 55
    .line 56
    add-int/lit8 v5, v5, -0x1

    .line 57
    .line 58
    iput v5, v4, Lka/a;->c:I

    .line 59
    .line 60
    :cond_2
    :goto_2
    add-int/lit8 p1, p1, 0x1

    .line 61
    .line 62
    goto :goto_4

    .line 63
    :cond_3
    if-ne p2, v2, :cond_4

    .line 64
    .line 65
    add-int/lit8 v3, v3, 0x1

    .line 66
    .line 67
    iput v3, v4, Lka/a;->b:I

    .line 68
    .line 69
    goto :goto_3

    .line 70
    :cond_4
    if-ne p2, v6, :cond_5

    .line 71
    .line 72
    add-int/lit8 v3, v3, -0x1

    .line 73
    .line 74
    iput v3, v4, Lka/a;->b:I

    .line 75
    .line 76
    :cond_5
    :goto_3
    add-int/lit8 p1, p1, -0x1

    .line 77
    .line 78
    goto :goto_4

    .line 79
    :cond_6
    if-ge p1, v3, :cond_c

    .line 80
    .line 81
    if-ne p2, v2, :cond_7

    .line 82
    .line 83
    add-int/lit8 v3, v3, 0x1

    .line 84
    .line 85
    iput v3, v4, Lka/a;->b:I

    .line 86
    .line 87
    add-int/lit8 v5, v5, 0x1

    .line 88
    .line 89
    iput v5, v4, Lka/a;->c:I

    .line 90
    .line 91
    goto :goto_4

    .line 92
    :cond_7
    if-ne p2, v6, :cond_c

    .line 93
    .line 94
    add-int/lit8 v3, v3, -0x1

    .line 95
    .line 96
    iput v3, v4, Lka/a;->b:I

    .line 97
    .line 98
    add-int/lit8 v5, v5, -0x1

    .line 99
    .line 100
    iput v5, v4, Lka/a;->c:I

    .line 101
    .line 102
    goto :goto_4

    .line 103
    :cond_8
    iget v3, v4, Lka/a;->b:I

    .line 104
    .line 105
    if-gt v3, p1, :cond_a

    .line 106
    .line 107
    if-ne v5, v2, :cond_9

    .line 108
    .line 109
    iget v3, v4, Lka/a;->c:I

    .line 110
    .line 111
    sub-int/2addr p1, v3

    .line 112
    goto :goto_4

    .line 113
    :cond_9
    if-ne v5, v6, :cond_c

    .line 114
    .line 115
    iget v3, v4, Lka/a;->c:I

    .line 116
    .line 117
    add-int/2addr p1, v3

    .line 118
    goto :goto_4

    .line 119
    :cond_a
    if-ne p2, v2, :cond_b

    .line 120
    .line 121
    add-int/lit8 v3, v3, 0x1

    .line 122
    .line 123
    iput v3, v4, Lka/a;->b:I

    .line 124
    .line 125
    goto :goto_4

    .line 126
    :cond_b
    if-ne p2, v6, :cond_c

    .line 127
    .line 128
    add-int/lit8 v3, v3, -0x1

    .line 129
    .line 130
    iput v3, v4, Lka/a;->b:I

    .line 131
    .line 132
    :cond_c
    :goto_4
    add-int/lit8 v1, v1, -0x1

    .line 133
    .line 134
    goto :goto_0

    .line 135
    :cond_d
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 136
    .line 137
    .line 138
    move-result p2

    .line 139
    sub-int/2addr p2, v2

    .line 140
    :goto_5
    if-ltz p2, :cond_11

    .line 141
    .line 142
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    check-cast v1, Lka/a;

    .line 147
    .line 148
    iget v2, v1, Lka/a;->a:I

    .line 149
    .line 150
    if-ne v2, v3, :cond_f

    .line 151
    .line 152
    iget v2, v1, Lka/a;->c:I

    .line 153
    .line 154
    iget v4, v1, Lka/a;->b:I

    .line 155
    .line 156
    if-eq v2, v4, :cond_e

    .line 157
    .line 158
    if-gez v2, :cond_10

    .line 159
    .line 160
    :cond_e
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v0, v1}, La5/e;->c(Ljava/lang/Object;)Z

    .line 164
    .line 165
    .line 166
    goto :goto_6

    .line 167
    :cond_f
    iget v2, v1, Lka/a;->c:I

    .line 168
    .line 169
    if-gtz v2, :cond_10

    .line 170
    .line 171
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    invoke-virtual {v0, v1}, La5/e;->c(Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    :cond_10
    :goto_6
    add-int/lit8 p2, p2, -0x1

    .line 178
    .line 179
    goto :goto_5

    .line 180
    :cond_11
    return p1
.end method

.method public K()V
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Lz9/s;

    .line 20
    .line 21
    iget v1, v1, Lz9/s;->a:I

    .line 22
    .line 23
    invoke-virtual {p0, v1}, Landroidx/lifecycle/c1;->s(I)Lz9/u;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    if-eqz v2, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    sget v0, Lz9/u;->h:I

    .line 31
    .line 32
    iget-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v0, Lca/d;

    .line 35
    .line 36
    invoke-static {v0, v1}, Ljp/q0;->c(Lca/d;I)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 41
    .line 42
    const-string v2, "Navigation destination "

    .line 43
    .line 44
    const-string v3, " cannot be found in the navigation graph "

    .line 45
    .line 46
    invoke-static {v2, v0, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    iget-object p0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, Lz9/v;

    .line 53
    .line 54
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v1

    .line 65
    :cond_1
    return-void
.end method

.method public a()Z
    .locals 4

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    move v2, v1

    .line 11
    :goto_0
    if-ge v2, v0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    check-cast v3, Lg4/r;

    .line 18
    .line 19
    iget-object v3, v3, Lg4/r;->a:Lo4/c;

    .line 20
    .line 21
    invoke-virtual {v3}, Lo4/c;->a()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-eqz v3, :cond_0

    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    return p0

    .line 29
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    return v1
.end method

.method public b()F
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public c()F
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Number;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public e(J)I
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, [J

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    invoke-static {p0, p1, p2, v0}, Lw7/w;->a([JJZ)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    array-length p0, p0

    .line 11
    if-ge p1, p0, :cond_0

    .line 12
    .line 13
    return p1

    .line 14
    :cond_0
    const/4 p0, -0x1

    .line 15
    return p0
.end method

.method public f(J)Ljava/util/List;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 4
    .line 5
    move-object v2, v1

    .line 6
    check-cast v2, Lr9/c;

    .line 7
    .line 8
    iget-object v1, v0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Ljava/util/Map;

    .line 11
    .line 12
    iget-object v3, v0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 13
    .line 14
    move-object v8, v3

    .line 15
    check-cast v8, Ljava/util/HashMap;

    .line 16
    .line 17
    iget-object v0, v0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Ljava/util/HashMap;

    .line 20
    .line 21
    new-instance v9, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    iget-object v3, v2, Lr9/c;->h:Ljava/lang/String;

    .line 27
    .line 28
    move-wide/from16 v4, p1

    .line 29
    .line 30
    invoke-virtual {v2, v4, v5, v3, v9}, Lr9/c;->g(JLjava/lang/String;Ljava/util/ArrayList;)V

    .line 31
    .line 32
    .line 33
    new-instance v7, Ljava/util/TreeMap;

    .line 34
    .line 35
    invoke-direct {v7}, Ljava/util/TreeMap;-><init>()V

    .line 36
    .line 37
    .line 38
    const/4 v5, 0x0

    .line 39
    iget-object v6, v2, Lr9/c;->h:Ljava/lang/String;

    .line 40
    .line 41
    move-wide/from16 v3, p1

    .line 42
    .line 43
    invoke-virtual/range {v2 .. v7}, Lr9/c;->i(JZLjava/lang/String;Ljava/util/TreeMap;)V

    .line 44
    .line 45
    .line 46
    iget-object v3, v2, Lr9/c;->h:Ljava/lang/String;

    .line 47
    .line 48
    move-object v5, v1

    .line 49
    move-object v6, v8

    .line 50
    move-object v8, v7

    .line 51
    move-object v7, v3

    .line 52
    move-wide/from16 v3, p1

    .line 53
    .line 54
    invoke-virtual/range {v2 .. v8}, Lr9/c;->h(JLjava/util/Map;Ljava/util/HashMap;Ljava/lang/String;Ljava/util/TreeMap;)V

    .line 55
    .line 56
    .line 57
    move-object v7, v8

    .line 58
    new-instance v1, Ljava/util/ArrayList;

    .line 59
    .line 60
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v9}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    const/4 v4, 0x0

    .line 72
    if-eqz v3, :cond_1

    .line 73
    .line 74
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v3

    .line 78
    check-cast v3, Landroid/util/Pair;

    .line 79
    .line 80
    iget-object v5, v3, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 81
    .line 82
    invoke-virtual {v0, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v5

    .line 86
    check-cast v5, Ljava/lang/String;

    .line 87
    .line 88
    if-nez v5, :cond_0

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_0
    invoke-static {v5, v4}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 92
    .line 93
    .line 94
    move-result-object v5

    .line 95
    array-length v8, v5

    .line 96
    invoke-static {v5, v4, v8}, Landroid/graphics/BitmapFactory;->decodeByteArray([BII)Landroid/graphics/Bitmap;

    .line 97
    .line 98
    .line 99
    move-result-object v13

    .line 100
    iget-object v3, v3, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 101
    .line 102
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    check-cast v3, Lr9/f;

    .line 107
    .line 108
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 109
    .line 110
    .line 111
    iget v4, v3, Lr9/f;->b:F

    .line 112
    .line 113
    iget v14, v3, Lr9/f;->c:F

    .line 114
    .line 115
    iget v5, v3, Lr9/f;->e:I

    .line 116
    .line 117
    iget v8, v3, Lr9/f;->f:F

    .line 118
    .line 119
    iget v9, v3, Lr9/f;->g:F

    .line 120
    .line 121
    iget v3, v3, Lr9/f;->j:I

    .line 122
    .line 123
    move/from16 v22, v9

    .line 124
    .line 125
    new-instance v9, Lv7/b;

    .line 126
    .line 127
    const/4 v10, 0x0

    .line 128
    const/4 v11, 0x0

    .line 129
    const/4 v15, 0x0

    .line 130
    const/16 v18, 0x0

    .line 131
    .line 132
    const/high16 v19, -0x80000000

    .line 133
    .line 134
    const v20, -0x800001

    .line 135
    .line 136
    .line 137
    const/16 v23, 0x0

    .line 138
    .line 139
    const/high16 v24, -0x1000000

    .line 140
    .line 141
    const/16 v26, 0x0

    .line 142
    .line 143
    const/16 v27, 0x0

    .line 144
    .line 145
    move-object v12, v11

    .line 146
    move/from16 v25, v3

    .line 147
    .line 148
    move/from16 v17, v4

    .line 149
    .line 150
    move/from16 v16, v5

    .line 151
    .line 152
    move/from16 v21, v8

    .line 153
    .line 154
    invoke-direct/range {v9 .. v27}, Lv7/b;-><init>(Ljava/lang/CharSequence;Landroid/text/Layout$Alignment;Landroid/text/Layout$Alignment;Landroid/graphics/Bitmap;FIIFIIFFFZIIFI)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v1, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    goto :goto_0

    .line 161
    :cond_1
    invoke-virtual {v7}, Ljava/util/TreeMap;->entrySet()Ljava/util/Set;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 170
    .line 171
    .line 172
    move-result v2

    .line 173
    if-eqz v2, :cond_d

    .line 174
    .line 175
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v2

    .line 179
    check-cast v2, Ljava/util/Map$Entry;

    .line 180
    .line 181
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    move-result-object v3

    .line 185
    invoke-virtual {v6, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    check-cast v3, Lr9/f;

    .line 190
    .line 191
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 192
    .line 193
    .line 194
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    check-cast v2, Lv7/a;

    .line 199
    .line 200
    iget-object v5, v2, Lv7/a;->a:Ljava/lang/CharSequence;

    .line 201
    .line 202
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 203
    .line 204
    .line 205
    check-cast v5, Landroid/text/SpannableStringBuilder;

    .line 206
    .line 207
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 208
    .line 209
    .line 210
    move-result v7

    .line 211
    const-class v8, Lr9/a;

    .line 212
    .line 213
    invoke-virtual {v5, v4, v7, v8}, Landroid/text/SpannableStringBuilder;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v7

    .line 217
    check-cast v7, [Lr9/a;

    .line 218
    .line 219
    array-length v8, v7

    .line 220
    move v9, v4

    .line 221
    :goto_2
    if-ge v9, v8, :cond_2

    .line 222
    .line 223
    aget-object v10, v7, v9

    .line 224
    .line 225
    invoke-virtual {v5, v10}, Landroid/text/SpannableStringBuilder;->getSpanStart(Ljava/lang/Object;)I

    .line 226
    .line 227
    .line 228
    move-result v11

    .line 229
    invoke-virtual {v5, v10}, Landroid/text/SpannableStringBuilder;->getSpanEnd(Ljava/lang/Object;)I

    .line 230
    .line 231
    .line 232
    move-result v10

    .line 233
    const-string v12, ""

    .line 234
    .line 235
    invoke-virtual {v5, v11, v10, v12}, Landroid/text/SpannableStringBuilder;->replace(IILjava/lang/CharSequence;)Landroid/text/SpannableStringBuilder;

    .line 236
    .line 237
    .line 238
    add-int/lit8 v9, v9, 0x1

    .line 239
    .line 240
    goto :goto_2

    .line 241
    :cond_2
    move v7, v4

    .line 242
    :goto_3
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 243
    .line 244
    .line 245
    move-result v8

    .line 246
    const/16 v9, 0x20

    .line 247
    .line 248
    if-ge v7, v8, :cond_5

    .line 249
    .line 250
    invoke-virtual {v5, v7}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 251
    .line 252
    .line 253
    move-result v8

    .line 254
    if-ne v8, v9, :cond_4

    .line 255
    .line 256
    add-int/lit8 v8, v7, 0x1

    .line 257
    .line 258
    move v10, v8

    .line 259
    :goto_4
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 260
    .line 261
    .line 262
    move-result v11

    .line 263
    if-ge v10, v11, :cond_3

    .line 264
    .line 265
    invoke-virtual {v5, v10}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 266
    .line 267
    .line 268
    move-result v11

    .line 269
    if-ne v11, v9, :cond_3

    .line 270
    .line 271
    add-int/lit8 v10, v10, 0x1

    .line 272
    .line 273
    goto :goto_4

    .line 274
    :cond_3
    sub-int/2addr v10, v8

    .line 275
    if-lez v10, :cond_4

    .line 276
    .line 277
    add-int/2addr v10, v7

    .line 278
    invoke-virtual {v5, v7, v10}, Landroid/text/SpannableStringBuilder;->delete(II)Landroid/text/SpannableStringBuilder;

    .line 279
    .line 280
    .line 281
    :cond_4
    add-int/lit8 v7, v7, 0x1

    .line 282
    .line 283
    goto :goto_3

    .line 284
    :cond_5
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 285
    .line 286
    .line 287
    move-result v7

    .line 288
    const/4 v8, 0x1

    .line 289
    if-lez v7, :cond_6

    .line 290
    .line 291
    invoke-virtual {v5, v4}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 292
    .line 293
    .line 294
    move-result v7

    .line 295
    if-ne v7, v9, :cond_6

    .line 296
    .line 297
    invoke-virtual {v5, v4, v8}, Landroid/text/SpannableStringBuilder;->delete(II)Landroid/text/SpannableStringBuilder;

    .line 298
    .line 299
    .line 300
    :cond_6
    move v7, v4

    .line 301
    :goto_5
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 302
    .line 303
    .line 304
    move-result v10

    .line 305
    sub-int/2addr v10, v8

    .line 306
    const/16 v11, 0xa

    .line 307
    .line 308
    if-ge v7, v10, :cond_8

    .line 309
    .line 310
    invoke-virtual {v5, v7}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 311
    .line 312
    .line 313
    move-result v10

    .line 314
    if-ne v10, v11, :cond_7

    .line 315
    .line 316
    add-int/lit8 v10, v7, 0x1

    .line 317
    .line 318
    invoke-virtual {v5, v10}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 319
    .line 320
    .line 321
    move-result v11

    .line 322
    if-ne v11, v9, :cond_7

    .line 323
    .line 324
    add-int/lit8 v11, v7, 0x2

    .line 325
    .line 326
    invoke-virtual {v5, v10, v11}, Landroid/text/SpannableStringBuilder;->delete(II)Landroid/text/SpannableStringBuilder;

    .line 327
    .line 328
    .line 329
    :cond_7
    add-int/lit8 v7, v7, 0x1

    .line 330
    .line 331
    goto :goto_5

    .line 332
    :cond_8
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 333
    .line 334
    .line 335
    move-result v7

    .line 336
    if-lez v7, :cond_9

    .line 337
    .line 338
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 339
    .line 340
    .line 341
    move-result v7

    .line 342
    sub-int/2addr v7, v8

    .line 343
    invoke-virtual {v5, v7}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 344
    .line 345
    .line 346
    move-result v7

    .line 347
    if-ne v7, v9, :cond_9

    .line 348
    .line 349
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 350
    .line 351
    .line 352
    move-result v7

    .line 353
    sub-int/2addr v7, v8

    .line 354
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 355
    .line 356
    .line 357
    move-result v10

    .line 358
    invoke-virtual {v5, v7, v10}, Landroid/text/SpannableStringBuilder;->delete(II)Landroid/text/SpannableStringBuilder;

    .line 359
    .line 360
    .line 361
    :cond_9
    move v7, v4

    .line 362
    :goto_6
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 363
    .line 364
    .line 365
    move-result v10

    .line 366
    sub-int/2addr v10, v8

    .line 367
    if-ge v7, v10, :cond_b

    .line 368
    .line 369
    invoke-virtual {v5, v7}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 370
    .line 371
    .line 372
    move-result v10

    .line 373
    if-ne v10, v9, :cond_a

    .line 374
    .line 375
    add-int/lit8 v10, v7, 0x1

    .line 376
    .line 377
    invoke-virtual {v5, v10}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 378
    .line 379
    .line 380
    move-result v12

    .line 381
    if-ne v12, v11, :cond_a

    .line 382
    .line 383
    invoke-virtual {v5, v7, v10}, Landroid/text/SpannableStringBuilder;->delete(II)Landroid/text/SpannableStringBuilder;

    .line 384
    .line 385
    .line 386
    :cond_a
    add-int/lit8 v7, v7, 0x1

    .line 387
    .line 388
    goto :goto_6

    .line 389
    :cond_b
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 390
    .line 391
    .line 392
    move-result v7

    .line 393
    if-lez v7, :cond_c

    .line 394
    .line 395
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 396
    .line 397
    .line 398
    move-result v7

    .line 399
    sub-int/2addr v7, v8

    .line 400
    invoke-virtual {v5, v7}, Landroid/text/SpannableStringBuilder;->charAt(I)C

    .line 401
    .line 402
    .line 403
    move-result v7

    .line 404
    if-ne v7, v11, :cond_c

    .line 405
    .line 406
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 407
    .line 408
    .line 409
    move-result v7

    .line 410
    sub-int/2addr v7, v8

    .line 411
    invoke-virtual {v5}, Landroid/text/SpannableStringBuilder;->length()I

    .line 412
    .line 413
    .line 414
    move-result v8

    .line 415
    invoke-virtual {v5, v7, v8}, Landroid/text/SpannableStringBuilder;->delete(II)Landroid/text/SpannableStringBuilder;

    .line 416
    .line 417
    .line 418
    :cond_c
    iget v5, v3, Lr9/f;->c:F

    .line 419
    .line 420
    iget v7, v3, Lr9/f;->d:I

    .line 421
    .line 422
    iput v5, v2, Lv7/a;->e:F

    .line 423
    .line 424
    iput v7, v2, Lv7/a;->f:I

    .line 425
    .line 426
    iget v5, v3, Lr9/f;->e:I

    .line 427
    .line 428
    iput v5, v2, Lv7/a;->g:I

    .line 429
    .line 430
    iget v5, v3, Lr9/f;->b:F

    .line 431
    .line 432
    iput v5, v2, Lv7/a;->h:F

    .line 433
    .line 434
    iget v5, v3, Lr9/f;->f:F

    .line 435
    .line 436
    iput v5, v2, Lv7/a;->l:F

    .line 437
    .line 438
    iget v5, v3, Lr9/f;->i:F

    .line 439
    .line 440
    iget v7, v3, Lr9/f;->h:I

    .line 441
    .line 442
    iput v5, v2, Lv7/a;->k:F

    .line 443
    .line 444
    iput v7, v2, Lv7/a;->j:I

    .line 445
    .line 446
    iget v3, v3, Lr9/f;->j:I

    .line 447
    .line 448
    iput v3, v2, Lv7/a;->p:I

    .line 449
    .line 450
    invoke-virtual {v2}, Lv7/a;->a()Lv7/b;

    .line 451
    .line 452
    .line 453
    move-result-object v2

    .line 454
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 455
    .line 456
    .line 457
    goto/16 :goto_1

    .line 458
    .line 459
    :cond_d
    return-object v1
.end method

.method public g(I)Ljava/text/Bidi;
    .locals 14

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/text/Layout;

    .line 4
    .line 5
    iget-object v1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    iget-object v2, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Ljava/util/ArrayList;

    .line 12
    .line 13
    iget-object v3, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v3, [Z

    .line 16
    .line 17
    aget-boolean v4, v3, p1

    .line 18
    .line 19
    if-eqz v4, :cond_0

    .line 20
    .line 21
    invoke-virtual {v2, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Ljava/text/Bidi;

    .line 26
    .line 27
    return-object p0

    .line 28
    :cond_0
    const/4 v4, 0x0

    .line 29
    if-nez p1, :cond_1

    .line 30
    .line 31
    move v5, v4

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    add-int/lit8 v5, p1, -0x1

    .line 34
    .line 35
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    check-cast v5, Ljava/lang/Number;

    .line 40
    .line 41
    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    .line 42
    .line 43
    .line 44
    move-result v5

    .line 45
    :goto_0
    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    check-cast v1, Ljava/lang/Number;

    .line 50
    .line 51
    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    sub-int v11, v1, v5

    .line 56
    .line 57
    iget-object v6, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v6, [C

    .line 60
    .line 61
    if-eqz v6, :cond_3

    .line 62
    .line 63
    array-length v7, v6

    .line 64
    if-ge v7, v11, :cond_2

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_2
    :goto_1
    move-object v7, v6

    .line 68
    goto :goto_3

    .line 69
    :cond_3
    :goto_2
    new-array v6, v11, [C

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :goto_3
    invoke-virtual {v0}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 73
    .line 74
    .line 75
    move-result-object v6

    .line 76
    invoke-static {v6, v5, v1, v7, v4}, Landroid/text/TextUtils;->getChars(Ljava/lang/CharSequence;II[CI)V

    .line 77
    .line 78
    .line 79
    invoke-static {v7, v4, v11}, Ljava/text/Bidi;->requiresBidi([CII)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    const/4 v5, 0x0

    .line 84
    const/4 v13, 0x1

    .line 85
    if-eqz v1, :cond_5

    .line 86
    .line 87
    invoke-virtual {p0, p1}, Landroidx/lifecycle/c1;->z(I)I

    .line 88
    .line 89
    .line 90
    move-result v1

    .line 91
    invoke-virtual {v0, v1}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    invoke-virtual {v0, v1}, Landroid/text/Layout;->getParagraphDirection(I)I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    const/4 v1, -0x1

    .line 100
    if-ne v0, v1, :cond_4

    .line 101
    .line 102
    move v12, v13

    .line 103
    goto :goto_4

    .line 104
    :cond_4
    move v12, v4

    .line 105
    :goto_4
    new-instance v6, Ljava/text/Bidi;

    .line 106
    .line 107
    const/4 v9, 0x0

    .line 108
    const/4 v10, 0x0

    .line 109
    const/4 v8, 0x0

    .line 110
    invoke-direct/range {v6 .. v12}, Ljava/text/Bidi;-><init>([CI[BIII)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v6}, Ljava/text/Bidi;->getRunCount()I

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-ne v0, v13, :cond_6

    .line 118
    .line 119
    :cond_5
    move-object v6, v5

    .line 120
    :cond_6
    invoke-virtual {v2, p1, v6}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    aput-boolean v13, v3, p1

    .line 124
    .line 125
    if-eqz v6, :cond_8

    .line 126
    .line 127
    iget-object p1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 128
    .line 129
    check-cast p1, [C

    .line 130
    .line 131
    if-ne v7, p1, :cond_7

    .line 132
    .line 133
    move-object v7, v5

    .line 134
    goto :goto_5

    .line 135
    :cond_7
    move-object v7, p1

    .line 136
    :cond_8
    :goto_5
    iput-object v7, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 137
    .line 138
    return-object v6
.end method

.method public get()Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Landroidx/lifecycle/c1;->d:I

    .line 2
    .line 3
    sparse-switch v0, :sswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lkx0/a;

    .line 9
    .line 10
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    move-object v2, v0

    .line 15
    check-cast v2, Ljava/util/concurrent/Executor;

    .line 16
    .line 17
    iget-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v0, Lkx0/a;

    .line 20
    .line 21
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    move-object v3, v0

    .line 26
    check-cast v3, Lsn/d;

    .line 27
    .line 28
    iget-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v0, Lrn/i;

    .line 31
    .line 32
    invoke-virtual {v0}, Lrn/i;->get()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    move-object v4, v0

    .line 37
    check-cast v4, Lrn/i;

    .line 38
    .line 39
    iget-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast v0, Lkx0/a;

    .line 42
    .line 43
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    move-object v5, v0

    .line 48
    check-cast v5, Lyn/d;

    .line 49
    .line 50
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p0, Lkx0/a;

    .line 53
    .line 54
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    move-object v6, p0

    .line 59
    check-cast v6, Lzn/c;

    .line 60
    .line 61
    new-instance v1, Lwn/a;

    .line 62
    .line 63
    invoke-direct/range {v1 .. v6}, Lwn/a;-><init>(Ljava/util/concurrent/Executor;Lsn/d;Lrn/i;Lyn/d;Lzn/c;)V

    .line 64
    .line 65
    .line 66
    return-object v1

    .line 67
    :sswitch_0
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v0, Lkx0/a;

    .line 70
    .line 71
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    move-object v2, v0

    .line 76
    check-cast v2, Lhu/a1;

    .line 77
    .line 78
    iget-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v0, Lkx0/a;

    .line 81
    .line 82
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    move-object v3, v0

    .line 87
    check-cast v3, Lht/d;

    .line 88
    .line 89
    iget-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v0, Lkx0/a;

    .line 92
    .line 93
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    move-object v4, v0

    .line 98
    check-cast v4, Lhu/b;

    .line 99
    .line 100
    iget-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 101
    .line 102
    check-cast v0, Lkx0/a;

    .line 103
    .line 104
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    move-object v5, v0

    .line 109
    check-cast v5, Lku/d;

    .line 110
    .line 111
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 112
    .line 113
    check-cast p0, Lju/c;

    .line 114
    .line 115
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    move-object v6, p0

    .line 120
    check-cast v6, Lku/m;

    .line 121
    .line 122
    new-instance v1, Lku/c;

    .line 123
    .line 124
    invoke-direct/range {v1 .. v6}, Lku/c;-><init>(Lhu/a1;Lht/d;Lhu/b;Lku/d;Lku/m;)V

    .line 125
    .line 126
    .line 127
    return-object v1

    .line 128
    :sswitch_1
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 129
    .line 130
    check-cast v0, Lj1/a;

    .line 131
    .line 132
    iget-object v0, v0, Lj1/a;->e:Ljava/lang/Object;

    .line 133
    .line 134
    move-object v2, v0

    .line 135
    check-cast v2, Lsr/f;

    .line 136
    .line 137
    iget-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 138
    .line 139
    check-cast v0, Lkx0/a;

    .line 140
    .line 141
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    move-object v3, v0

    .line 146
    check-cast v3, Lht/d;

    .line 147
    .line 148
    iget-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v0, Lkx0/a;

    .line 151
    .line 152
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    move-object v4, v0

    .line 157
    check-cast v4, Lku/j;

    .line 158
    .line 159
    iget-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 160
    .line 161
    check-cast v0, Lju/c;

    .line 162
    .line 163
    invoke-interface {v0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    move-object v5, v0

    .line 168
    check-cast v5, Lhu/l;

    .line 169
    .line 170
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 171
    .line 172
    check-cast p0, Lkx0/a;

    .line 173
    .line 174
    invoke-interface {p0}, Lkx0/a;->get()Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    move-object v6, p0

    .line 179
    check-cast v6, Lpx0/g;

    .line 180
    .line 181
    new-instance v1, Lhu/o0;

    .line 182
    .line 183
    invoke-direct/range {v1 .. v6}, Lhu/o0;-><init>(Lsr/f;Lht/d;Lku/j;Lhu/l;Lpx0/g;)V

    .line 184
    .line 185
    .line 186
    return-object v1

    .line 187
    :sswitch_data_0
    .sparse-switch
        0x9 -> :sswitch_1
        0xf -> :sswitch_0
    .end sparse-switch
.end method

.method public getValue()Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroidx/lifecycle/b1;

    .line 4
    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    iget-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lq61/n;

    .line 10
    .line 11
    invoke-virtual {v0}, Lq61/n;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Landroidx/lifecycle/h1;

    .line 16
    .line 17
    iget-object v1, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lay0/a;

    .line 20
    .line 21
    invoke-interface {v1}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Landroidx/lifecycle/e1;

    .line 26
    .line 27
    iget-object v2, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, Lq61/n;

    .line 30
    .line 31
    invoke-virtual {v2}, Lq61/n;->invoke()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    check-cast v2, Lp7/c;

    .line 36
    .line 37
    const-string v3, "store"

    .line 38
    .line 39
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    const-string v3, "factory"

    .line 43
    .line 44
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    const-string v3, "extras"

    .line 48
    .line 49
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    new-instance v3, Lcom/google/firebase/messaging/w;

    .line 53
    .line 54
    invoke-direct {v3, v0, v1, v2}, Lcom/google/firebase/messaging/w;-><init>(Landroidx/lifecycle/h1;Landroidx/lifecycle/e1;Lp7/c;)V

    .line 55
    .line 56
    .line 57
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, Lhy0/d;

    .line 60
    .line 61
    const-string v1, "modelClass"

    .line 62
    .line 63
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    invoke-interface {v0}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    if-eqz v1, :cond_0

    .line 71
    .line 72
    const-string v2, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    .line 73
    .line 74
    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v1

    .line 78
    invoke-virtual {v3, v0, v1}, Lcom/google/firebase/messaging/w;->l(Lhy0/d;Ljava/lang/String;)Landroidx/lifecycle/b1;

    .line 79
    .line 80
    .line 81
    move-result-object v0

    .line 82
    iput-object v0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 83
    .line 84
    return-object v0

    .line 85
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 86
    .line 87
    const-string v0, "Local and anonymous classes can not be ViewModels"

    .line 88
    .line 89
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_1
    return-object v0
.end method

.method public h()Lh0/i;
    .locals 8

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lh0/t0;

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, " surface"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const-string v0, ""

    .line 11
    .line 12
    :goto_0
    iget-object v1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v1, Ljava/util/List;

    .line 15
    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    const-string v1, " sharedSurfaces"

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :cond_1
    iget-object v1, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Ljava/lang/Integer;

    .line 27
    .line 28
    if-nez v1, :cond_2

    .line 29
    .line 30
    const-string v1, " mirrorMode"

    .line 31
    .line 32
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    :cond_2
    iget-object v1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v1, Ljava/lang/Integer;

    .line 39
    .line 40
    if-nez v1, :cond_3

    .line 41
    .line 42
    const-string v1, " surfaceGroupId"

    .line 43
    .line 44
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    :cond_3
    iget-object v1, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 49
    .line 50
    check-cast v1, Lb0/y;

    .line 51
    .line 52
    if-nez v1, :cond_4

    .line 53
    .line 54
    const-string v1, " dynamicRange"

    .line 55
    .line 56
    invoke-static {v0, v1}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    :cond_4
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_5

    .line 65
    .line 66
    new-instance v2, Lh0/i;

    .line 67
    .line 68
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 69
    .line 70
    move-object v3, v0

    .line 71
    check-cast v3, Lh0/t0;

    .line 72
    .line 73
    iget-object v0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 74
    .line 75
    move-object v4, v0

    .line 76
    check-cast v4, Ljava/util/List;

    .line 77
    .line 78
    iget-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v0, Ljava/lang/Integer;

    .line 81
    .line 82
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 83
    .line 84
    .line 85
    move-result v5

    .line 86
    iget-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v0, Ljava/lang/Integer;

    .line 89
    .line 90
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 91
    .line 92
    .line 93
    move-result v6

    .line 94
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 95
    .line 96
    move-object v7, p0

    .line 97
    check-cast v7, Lb0/y;

    .line 98
    .line 99
    invoke-direct/range {v2 .. v7}, Lh0/i;-><init>(Lh0/t0;Ljava/util/List;IILb0/y;)V

    .line 100
    .line 101
    .line 102
    return-object v2

    .line 103
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 104
    .line 105
    const-string v1, "Missing required properties:"

    .line 106
    .line 107
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0
.end method

.method public i(I)J
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, [J

    .line 4
    .line 5
    aget-wide p0, p0, p1

    .line 6
    .line 7
    return-wide p0
.end method

.method public isInitialized()Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/lifecycle/b1;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public j(I)Z
    .locals 8

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x0

    .line 10
    move v3, v2

    .line 11
    :goto_0
    if-ge v3, v1, :cond_3

    .line 12
    .line 13
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v4

    .line 17
    check-cast v4, Lka/a;

    .line 18
    .line 19
    iget v5, v4, Lka/a;->a:I

    .line 20
    .line 21
    const/16 v6, 0x8

    .line 22
    .line 23
    const/4 v7, 0x1

    .line 24
    if-ne v5, v6, :cond_0

    .line 25
    .line 26
    iget v4, v4, Lka/a;->c:I

    .line 27
    .line 28
    add-int/lit8 v5, v3, 0x1

    .line 29
    .line 30
    invoke-virtual {p0, v4, v5}, Landroidx/lifecycle/c1;->t(II)I

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    if-ne v4, p1, :cond_2

    .line 35
    .line 36
    goto :goto_2

    .line 37
    :cond_0
    if-ne v5, v7, :cond_2

    .line 38
    .line 39
    iget v5, v4, Lka/a;->b:I

    .line 40
    .line 41
    iget v4, v4, Lka/a;->c:I

    .line 42
    .line 43
    add-int/2addr v4, v5

    .line 44
    :goto_1
    if-ge v5, v4, :cond_2

    .line 45
    .line 46
    add-int/lit8 v6, v3, 0x1

    .line 47
    .line 48
    invoke-virtual {p0, v5, v6}, Landroidx/lifecycle/c1;->t(II)I

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-ne v6, p1, :cond_1

    .line 53
    .line 54
    :goto_2
    return v7

    .line 55
    :cond_1
    add-int/lit8 v5, v5, 0x1

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    return v2
.end method

.method public k()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, [J

    .line 4
    .line 5
    array-length p0, p0

    .line 6
    return p0
.end method

.method public l()V
    .locals 8

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lhu/q;

    .line 4
    .line 5
    iget-object v1, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    const/4 v3, 0x0

    .line 14
    :goto_0
    if-ge v3, v2, :cond_0

    .line 15
    .line 16
    iget-object v4, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v4, Lhu/q;

    .line 19
    .line 20
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    check-cast v5, Lka/a;

    .line 25
    .line 26
    invoke-virtual {v4, v5}, Lhu/q;->y(Lka/a;)V

    .line 27
    .line 28
    .line 29
    add-int/lit8 v3, v3, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {p0, v1}, Landroidx/lifecycle/c1;->H(Ljava/util/ArrayList;)V

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast v1, Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    const/4 v3, 0x0

    .line 44
    :goto_1
    if-ge v3, v2, :cond_5

    .line 45
    .line 46
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    check-cast v4, Lka/a;

    .line 51
    .line 52
    iget v5, v4, Lka/a;->a:I

    .line 53
    .line 54
    const/4 v6, 0x1

    .line 55
    if-eq v5, v6, :cond_4

    .line 56
    .line 57
    const/4 v7, 0x2

    .line 58
    if-eq v5, v7, :cond_3

    .line 59
    .line 60
    const/4 v6, 0x4

    .line 61
    if-eq v5, v6, :cond_2

    .line 62
    .line 63
    const/16 v6, 0x8

    .line 64
    .line 65
    if-eq v5, v6, :cond_1

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_1
    invoke-virtual {v0, v4}, Lhu/q;->y(Lka/a;)V

    .line 69
    .line 70
    .line 71
    iget v5, v4, Lka/a;->b:I

    .line 72
    .line 73
    iget v4, v4, Lka/a;->c:I

    .line 74
    .line 75
    invoke-virtual {v0, v5, v4}, Lhu/q;->L(II)V

    .line 76
    .line 77
    .line 78
    goto :goto_2

    .line 79
    :cond_2
    invoke-virtual {v0, v4}, Lhu/q;->y(Lka/a;)V

    .line 80
    .line 81
    .line 82
    iget v5, v4, Lka/a;->b:I

    .line 83
    .line 84
    iget v4, v4, Lka/a;->c:I

    .line 85
    .line 86
    invoke-virtual {v0, v5, v4}, Lhu/q;->H(II)V

    .line 87
    .line 88
    .line 89
    goto :goto_2

    .line 90
    :cond_3
    invoke-virtual {v0, v4}, Lhu/q;->y(Lka/a;)V

    .line 91
    .line 92
    .line 93
    iget v5, v4, Lka/a;->b:I

    .line 94
    .line 95
    iget v4, v4, Lka/a;->c:I

    .line 96
    .line 97
    iget-object v7, v0, Lhu/q;->e:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v7, Landroidx/recyclerview/widget/RecyclerView;

    .line 100
    .line 101
    invoke-virtual {v7, v5, v4, v6}, Landroidx/recyclerview/widget/RecyclerView;->P(IIZ)V

    .line 102
    .line 103
    .line 104
    iput-boolean v6, v7, Landroidx/recyclerview/widget/RecyclerView;->t1:Z

    .line 105
    .line 106
    iget-object v5, v7, Landroidx/recyclerview/widget/RecyclerView;->q1:Lka/r0;

    .line 107
    .line 108
    iget v6, v5, Lka/r0;->c:I

    .line 109
    .line 110
    add-int/2addr v6, v4

    .line 111
    iput v6, v5, Lka/r0;->c:I

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_4
    invoke-virtual {v0, v4}, Lhu/q;->y(Lka/a;)V

    .line 115
    .line 116
    .line 117
    iget v5, v4, Lka/a;->b:I

    .line 118
    .line 119
    iget v4, v4, Lka/a;->c:I

    .line 120
    .line 121
    invoke-virtual {v0, v5, v4}, Lhu/q;->K(II)V

    .line 122
    .line 123
    .line 124
    :goto_2
    add-int/lit8 v3, v3, 0x1

    .line 125
    .line 126
    goto :goto_1

    .line 127
    :cond_5
    invoke-virtual {p0, v1}, Landroidx/lifecycle/c1;->H(Ljava/util/ArrayList;)V

    .line 128
    .line 129
    .line 130
    return-void
.end method

.method public m(Lh0/b0;Lh0/b0;Lp0/k;Lp0/k;Ljava/util/Map$Entry;)V
    .locals 10

    .line 1
    invoke-interface {p5}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v2, v0

    .line 6
    check-cast v2, Lp0/k;

    .line 7
    .line 8
    new-instance v0, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v1, "     -> outputEdge = "

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    const-string v1, "DualSurfaceProcessorNode"

    .line 23
    .line 24
    invoke-static {v1, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    iget-object v0, p3, Lp0/k;->g:Lh0/k;

    .line 28
    .line 29
    iget-object v4, v0, Lh0/k;->a:Landroid/util/Size;

    .line 30
    .line 31
    invoke-interface {p5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    check-cast v0, Lq0/a;

    .line 36
    .line 37
    iget-object v0, v0, Lq0/a;->a:Lr0/b;

    .line 38
    .line 39
    iget-object v5, v0, Lr0/b;->d:Landroid/graphics/Rect;

    .line 40
    .line 41
    iget-boolean p3, p3, Lp0/k;->c:Z

    .line 42
    .line 43
    const/4 v0, 0x0

    .line 44
    if-eqz p3, :cond_0

    .line 45
    .line 46
    move-object v6, p1

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    move-object v6, v0

    .line 49
    :goto_0
    invoke-interface {p5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    check-cast p1, Lq0/a;

    .line 54
    .line 55
    iget-object p1, p1, Lq0/a;->a:Lr0/b;

    .line 56
    .line 57
    iget v7, p1, Lr0/b;->f:I

    .line 58
    .line 59
    invoke-interface {p5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    check-cast p1, Lq0/a;

    .line 64
    .line 65
    iget-object p1, p1, Lq0/a;->a:Lr0/b;

    .line 66
    .line 67
    iget-boolean v8, p1, Lr0/b;->g:Z

    .line 68
    .line 69
    new-instance v3, Lb0/g;

    .line 70
    .line 71
    invoke-direct/range {v3 .. v8}, Lb0/g;-><init>(Landroid/util/Size;Landroid/graphics/Rect;Lh0/b0;IZ)V

    .line 72
    .line 73
    .line 74
    iget-object p1, p4, Lp0/k;->g:Lh0/k;

    .line 75
    .line 76
    iget-object v5, p1, Lh0/k;->a:Landroid/util/Size;

    .line 77
    .line 78
    invoke-interface {p5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    check-cast p1, Lq0/a;

    .line 83
    .line 84
    iget-object p1, p1, Lq0/a;->b:Lr0/b;

    .line 85
    .line 86
    iget-object v6, p1, Lr0/b;->d:Landroid/graphics/Rect;

    .line 87
    .line 88
    iget-boolean p1, p4, Lp0/k;->c:Z

    .line 89
    .line 90
    if-eqz p1, :cond_1

    .line 91
    .line 92
    move-object v7, p2

    .line 93
    goto :goto_1

    .line 94
    :cond_1
    move-object v7, v0

    .line 95
    :goto_1
    invoke-interface {p5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    check-cast p1, Lq0/a;

    .line 100
    .line 101
    iget-object p1, p1, Lq0/a;->b:Lr0/b;

    .line 102
    .line 103
    iget v8, p1, Lr0/b;->f:I

    .line 104
    .line 105
    invoke-interface {p5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    check-cast p1, Lq0/a;

    .line 110
    .line 111
    iget-object p1, p1, Lq0/a;->b:Lr0/b;

    .line 112
    .line 113
    iget-boolean v9, p1, Lr0/b;->g:Z

    .line 114
    .line 115
    new-instance v4, Lb0/g;

    .line 116
    .line 117
    invoke-direct/range {v4 .. v9}, Lb0/g;-><init>(Landroid/util/Size;Landroid/graphics/Rect;Lh0/b0;IZ)V

    .line 118
    .line 119
    .line 120
    invoke-interface {p5}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    check-cast p1, Lq0/a;

    .line 125
    .line 126
    iget-object p1, p1, Lq0/a;->a:Lr0/b;

    .line 127
    .line 128
    iget p1, p1, Lr0/b;->c:I

    .line 129
    .line 130
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    invoke-static {}, Llp/k1;->a()V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v2}, Lp0/k;->a()V

    .line 137
    .line 138
    .line 139
    iget-boolean p2, v2, Lp0/k;->j:Z

    .line 140
    .line 141
    const/4 p3, 0x1

    .line 142
    xor-int/2addr p2, p3

    .line 143
    const-string p4, "Consumer can only be linked once."

    .line 144
    .line 145
    invoke-static {p4, p2}, Ljp/ed;->f(Ljava/lang/String;Z)V

    .line 146
    .line 147
    .line 148
    iput-boolean p3, v2, Lp0/k;->j:Z

    .line 149
    .line 150
    move-object v5, v3

    .line 151
    iget-object v3, v2, Lp0/k;->l:Lp0/j;

    .line 152
    .line 153
    invoke-virtual {v3}, Lh0/t0;->c()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 154
    .line 155
    .line 156
    move-result-object p2

    .line 157
    new-instance v1, Lp0/h;

    .line 158
    .line 159
    move-object v6, v4

    .line 160
    move v4, p1

    .line 161
    invoke-direct/range {v1 .. v6}, Lp0/h;-><init>(Lp0/k;Lp0/j;ILb0/g;Lb0/g;)V

    .line 162
    .line 163
    .line 164
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 165
    .line 166
    .line 167
    move-result-object p1

    .line 168
    invoke-static {p2, v1, p1}, Lk0/h;->g(Lcom/google/common/util/concurrent/ListenableFuture;Lk0/a;Ljava/util/concurrent/Executor;)Lk0/b;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    new-instance p2, Lb81/d;

    .line 173
    .line 174
    const/16 p3, 0x13

    .line 175
    .line 176
    const/4 p4, 0x0

    .line 177
    invoke-direct {p2, p0, v2, p4, p3}, Lb81/d;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 178
    .line 179
    .line 180
    invoke-static {}, Llp/hb;->d()Lj0/c;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    new-instance p3, Lk0/g;

    .line 185
    .line 186
    invoke-direct {p3, p4, p1, p2}, Lk0/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    invoke-virtual {p1, p0, p3}, Lk0/d;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 190
    .line 191
    .line 192
    return-void
.end method

.method public n()V
    .locals 8

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lap0/o;

    .line 4
    .line 5
    const-string v1, "Create eager instances ..."

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Lap0/o;->u(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    invoke-static {}, Lmy0/j;->b()J

    .line 11
    .line 12
    .line 13
    move-result-wide v0

    .line 14
    iget-object v2, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Lgw0/c;

    .line 17
    .line 18
    iget-object v3, v2, Lgw0/c;->g:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v3, Ljava/util/concurrent/ConcurrentHashMap;

    .line 21
    .line 22
    invoke-virtual {v3}, Ljava/util/concurrent/ConcurrentHashMap;->values()Ljava/util/Collection;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    const/4 v5, 0x0

    .line 27
    new-array v5, v5, [Lc21/d;

    .line 28
    .line 29
    invoke-interface {v4, v5}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object v4

    .line 33
    check-cast v4, [Lc21/d;

    .line 34
    .line 35
    array-length v5, v4

    .line 36
    invoke-static {v4, v5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v4

    .line 40
    invoke-static {v4}, Ljp/k1;->b([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 41
    .line 42
    .line 43
    move-result-object v4

    .line 44
    invoke-virtual {v3}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 45
    .line 46
    .line 47
    new-instance v3, Lu/x0;

    .line 48
    .line 49
    iget-object v2, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v2, Landroidx/lifecycle/c1;

    .line 52
    .line 53
    iget-object v5, v2, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 54
    .line 55
    check-cast v5, Lap0/o;

    .line 56
    .line 57
    iget-object v2, v2, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v2, Li21/b;

    .line 60
    .line 61
    iget-object v2, v2, Li21/b;->d:Lk21/a;

    .line 62
    .line 63
    const-class v6, Lc21/c;

    .line 64
    .line 65
    sget-object v7, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 66
    .line 67
    invoke-virtual {v7, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    invoke-direct {v3, v5, v2, v6}, Lu/x0;-><init>(Lap0/o;Lk21/a;Lhy0/d;)V

    .line 72
    .line 73
    .line 74
    invoke-virtual {v4}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 79
    .line 80
    .line 81
    move-result v4

    .line 82
    if-eqz v4, :cond_0

    .line 83
    .line 84
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v4

    .line 88
    check-cast v4, Lc21/d;

    .line 89
    .line 90
    invoke-virtual {v4, v3}, Lc21/d;->c(Lu/x0;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    goto :goto_0

    .line 94
    :cond_0
    invoke-static {v0, v1}, Lmy0/l;->a(J)J

    .line 95
    .line 96
    .line 97
    move-result-wide v0

    .line 98
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Lap0/o;

    .line 101
    .line 102
    new-instance v2, Ljava/lang/StringBuilder;

    .line 103
    .line 104
    const-string v3, "Created eager instances in "

    .line 105
    .line 106
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    sget v3, Lmy0/c;->g:I

    .line 110
    .line 111
    sget-object v3, Lmy0/e;->f:Lmy0/e;

    .line 112
    .line 113
    invoke-static {v0, v1, v3}, Lmy0/c;->n(JLmy0/e;)J

    .line 114
    .line 115
    .line 116
    move-result-wide v0

    .line 117
    long-to-double v0, v0

    .line 118
    const-wide v3, 0x408f400000000000L    # 1000.0

    .line 119
    .line 120
    .line 121
    .line 122
    .line 123
    div-double/2addr v0, v3

    .line 124
    invoke-virtual {v2, v0, v1}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    const-string v0, " ms"

    .line 128
    .line 129
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 130
    .line 131
    .line 132
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    invoke-virtual {p0, v0}, Lap0/o;->u(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    return-void
.end method

.method public p()Landroidx/core/app/m0;
    .locals 11

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/ArrayList;

    .line 4
    .line 5
    iget-object v1, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroid/content/Intent;

    .line 8
    .line 9
    iget-object v2, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v2, Lz9/v;

    .line 12
    .line 13
    if-eqz v2, :cond_6

    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    if-nez v3, :cond_5

    .line 20
    .line 21
    new-instance v3, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    new-instance v4, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    const/4 v5, 0x0

    .line 36
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 37
    .line 38
    .line 39
    move-result v6

    .line 40
    const/4 v7, 0x0

    .line 41
    if-eqz v6, :cond_2

    .line 42
    .line 43
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    check-cast v6, Lz9/s;

    .line 48
    .line 49
    iget v8, v6, Lz9/s;->a:I

    .line 50
    .line 51
    iget-object v6, v6, Lz9/s;->b:Landroid/os/Bundle;

    .line 52
    .line 53
    invoke-virtual {p0, v8}, Landroidx/lifecycle/c1;->s(I)Lz9/u;

    .line 54
    .line 55
    .line 56
    move-result-object v9

    .line 57
    if-eqz v9, :cond_1

    .line 58
    .line 59
    invoke-virtual {v9, v5}, Lz9/u;->g(Lz9/u;)[I

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    array-length v8, v5

    .line 64
    :goto_1
    if-ge v7, v8, :cond_0

    .line 65
    .line 66
    aget v10, v5, v7

    .line 67
    .line 68
    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 69
    .line 70
    .line 71
    move-result-object v10

    .line 72
    invoke-virtual {v3, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    invoke-virtual {v4, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    add-int/lit8 v7, v7, 0x1

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_0
    move-object v5, v9

    .line 82
    goto :goto_0

    .line 83
    :cond_1
    sget v0, Lz9/u;->h:I

    .line 84
    .line 85
    iget-object p0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast p0, Lca/d;

    .line 88
    .line 89
    invoke-static {p0, v8}, Ljp/q0;->c(Lca/d;I)Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 94
    .line 95
    new-instance v1, Ljava/lang/StringBuilder;

    .line 96
    .line 97
    const-string v3, "Navigation destination "

    .line 98
    .line 99
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string p0, " cannot be found in the navigation graph "

    .line 106
    .line 107
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 118
    .line 119
    .line 120
    throw v0

    .line 121
    :cond_2
    invoke-static {v3}, Lmx0/q;->w0(Ljava/util/Collection;)[I

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    const-string v2, "android-support-nav:controller:deepLinkIds"

    .line 126
    .line 127
    invoke-virtual {v1, v2, v0}, Landroid/content/Intent;->putExtra(Ljava/lang/String;[I)Landroid/content/Intent;

    .line 128
    .line 129
    .line 130
    const-string v0, "android-support-nav:controller:deepLinkArgs"

    .line 131
    .line 132
    invoke-virtual {v1, v0, v4}, Landroid/content/Intent;->putParcelableArrayListExtra(Ljava/lang/String;Ljava/util/ArrayList;)Landroid/content/Intent;

    .line 133
    .line 134
    .line 135
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast p0, Landroid/content/Context;

    .line 138
    .line 139
    new-instance v0, Landroidx/core/app/m0;

    .line 140
    .line 141
    invoke-direct {v0, p0}, Landroidx/core/app/m0;-><init>(Landroid/content/Context;)V

    .line 142
    .line 143
    .line 144
    new-instance p0, Landroid/content/Intent;

    .line 145
    .line 146
    invoke-direct {p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Intent;)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0, p0}, Landroidx/core/app/m0;->c(Landroid/content/Intent;)V

    .line 150
    .line 151
    .line 152
    iget-object p0, v0, Landroidx/core/app/m0;->d:Ljava/util/ArrayList;

    .line 153
    .line 154
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    :goto_2
    if-ge v7, v2, :cond_4

    .line 159
    .line 160
    invoke-virtual {p0, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v3

    .line 164
    check-cast v3, Landroid/content/Intent;

    .line 165
    .line 166
    if-eqz v3, :cond_3

    .line 167
    .line 168
    const-string v4, "android-support-nav:controller:deepLinkIntent"

    .line 169
    .line 170
    invoke-virtual {v3, v4, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;

    .line 171
    .line 172
    .line 173
    :cond_3
    add-int/lit8 v7, v7, 0x1

    .line 174
    .line 175
    goto :goto_2

    .line 176
    :cond_4
    return-object v0

    .line 177
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 178
    .line 179
    const-string v0, "You must call setDestination() or addDestination() before constructing the deep link"

    .line 180
    .line 181
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 182
    .line 183
    .line 184
    throw p0

    .line 185
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 186
    .line 187
    const-string v0, "You must call setGraph() before constructing the deep link"

    .line 188
    .line 189
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 190
    .line 191
    .line 192
    throw p0
.end method

.method public q(Lka/a;)V
    .locals 12

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, La5/e;

    .line 4
    .line 5
    iget v1, p1, Lka/a;->a:I

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    if-eq v1, v2, :cond_8

    .line 9
    .line 10
    const/16 v3, 0x8

    .line 11
    .line 12
    if-eq v1, v3, :cond_8

    .line 13
    .line 14
    iget v3, p1, Lka/a;->b:I

    .line 15
    .line 16
    invoke-virtual {p0, v3, v1}, Landroidx/lifecycle/c1;->J(II)I

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    iget v3, p1, Lka/a;->b:I

    .line 21
    .line 22
    iget v4, p1, Lka/a;->a:I

    .line 23
    .line 24
    const/4 v5, 0x2

    .line 25
    const/4 v6, 0x4

    .line 26
    if-eq v4, v5, :cond_1

    .line 27
    .line 28
    if-ne v4, v6, :cond_0

    .line 29
    .line 30
    move v4, v2

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    new-instance v0, Ljava/lang/StringBuilder;

    .line 35
    .line 36
    const-string v1, "op should be remove or update."

    .line 37
    .line 38
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_1
    const/4 v4, 0x0

    .line 53
    :goto_0
    move v7, v2

    .line 54
    move v8, v7

    .line 55
    :goto_1
    iget v9, p1, Lka/a;->c:I

    .line 56
    .line 57
    if-ge v7, v9, :cond_6

    .line 58
    .line 59
    iget v9, p1, Lka/a;->b:I

    .line 60
    .line 61
    mul-int v10, v4, v7

    .line 62
    .line 63
    add-int/2addr v10, v9

    .line 64
    iget v9, p1, Lka/a;->a:I

    .line 65
    .line 66
    invoke-virtual {p0, v10, v9}, Landroidx/lifecycle/c1;->J(II)I

    .line 67
    .line 68
    .line 69
    move-result v9

    .line 70
    iget v10, p1, Lka/a;->a:I

    .line 71
    .line 72
    if-eq v10, v5, :cond_3

    .line 73
    .line 74
    if-eq v10, v6, :cond_2

    .line 75
    .line 76
    goto :goto_3

    .line 77
    :cond_2
    add-int/lit8 v11, v1, 0x1

    .line 78
    .line 79
    if-ne v9, v11, :cond_4

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_3
    if-ne v9, v1, :cond_4

    .line 83
    .line 84
    :goto_2
    add-int/lit8 v8, v8, 0x1

    .line 85
    .line 86
    goto :goto_4

    .line 87
    :cond_4
    :goto_3
    invoke-virtual {p0, v10, v1, v8}, Landroidx/lifecycle/c1;->E(III)Lka/a;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    invoke-virtual {p0, v1, v3}, Landroidx/lifecycle/c1;->r(Lka/a;I)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {v0, v1}, La5/e;->c(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    iget v1, p1, Lka/a;->a:I

    .line 98
    .line 99
    if-ne v1, v6, :cond_5

    .line 100
    .line 101
    add-int/2addr v3, v8

    .line 102
    :cond_5
    move v8, v2

    .line 103
    move v1, v9

    .line 104
    :goto_4
    add-int/lit8 v7, v7, 0x1

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_6
    invoke-virtual {v0, p1}, La5/e;->c(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    if-lez v8, :cond_7

    .line 111
    .line 112
    iget p1, p1, Lka/a;->a:I

    .line 113
    .line 114
    invoke-virtual {p0, p1, v1, v8}, Landroidx/lifecycle/c1;->E(III)Lka/a;

    .line 115
    .line 116
    .line 117
    move-result-object p1

    .line 118
    invoke-virtual {p0, p1, v3}, Landroidx/lifecycle/c1;->r(Lka/a;I)V

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0, p1}, La5/e;->c(Ljava/lang/Object;)Z

    .line 122
    .line 123
    .line 124
    :cond_7
    return-void

    .line 125
    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 126
    .line 127
    const-string p1, "should not dispatch add or move for pre layout"

    .line 128
    .line 129
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p0
.end method

.method public r(Lka/a;I)V
    .locals 2

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lhu/q;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lhu/q;->y(Lka/a;)V

    .line 6
    .line 7
    .line 8
    iget v0, p1, Lka/a;->a:I

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    if-eq v0, v1, :cond_1

    .line 12
    .line 13
    const/4 v1, 0x4

    .line 14
    if-ne v0, v1, :cond_0

    .line 15
    .line 16
    iget p1, p1, Lka/a;->c:I

    .line 17
    .line 18
    invoke-virtual {p0, p2, p1}, Lhu/q;->H(II)V

    .line 19
    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 23
    .line 24
    const-string p1, "only remove and update ops can be dispatched in first pass"

    .line 25
    .line 26
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    iget p1, p1, Lka/a;->c:I

    .line 31
    .line 32
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 35
    .line 36
    const/4 v0, 0x1

    .line 37
    invoke-virtual {p0, p2, p1, v0}, Landroidx/recyclerview/widget/RecyclerView;->P(IIZ)V

    .line 38
    .line 39
    .line 40
    iput-boolean v0, p0, Landroidx/recyclerview/widget/RecyclerView;->t1:Z

    .line 41
    .line 42
    iget-object p0, p0, Landroidx/recyclerview/widget/RecyclerView;->q1:Lka/r0;

    .line 43
    .line 44
    iget p2, p0, Lka/r0;->c:I

    .line 45
    .line 46
    add-int/2addr p2, p1

    .line 47
    iput p2, p0, Lka/r0;->c:I

    .line 48
    .line 49
    return-void
.end method

.method public s(I)Lz9/u;
    .locals 3

    .line 1
    new-instance v0, Lmx0/l;

    .line 2
    .line 3
    invoke-direct {v0}, Lmx0/l;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lz9/v;

    .line 9
    .line 10
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, p0}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    :cond_0
    invoke-virtual {v0}, Lmx0/l;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    if-nez p0, :cond_2

    .line 21
    .line 22
    invoke-virtual {v0}, Lmx0/l;->removeFirst()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    check-cast p0, Lz9/u;

    .line 27
    .line 28
    iget-object v1, p0, Lz9/u;->e:Lca/j;

    .line 29
    .line 30
    iget v1, v1, Lca/j;->a:I

    .line 31
    .line 32
    if-ne v1, p1, :cond_1

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_1
    instance-of v1, p0, Lz9/v;

    .line 36
    .line 37
    if-eqz v1, :cond_0

    .line 38
    .line 39
    check-cast p0, Lz9/v;

    .line 40
    .line 41
    invoke-virtual {p0}, Lz9/v;->iterator()Ljava/util/Iterator;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    :goto_0
    move-object v1, p0

    .line 46
    check-cast v1, Lca/l;

    .line 47
    .line 48
    invoke-virtual {v1}, Lca/l;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_0

    .line 53
    .line 54
    invoke-virtual {v1}, Lca/l;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    check-cast v1, Lz9/u;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_2
    const/4 p0, 0x0

    .line 65
    return-object p0
.end method

.method public t(II)I
    .locals 5

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    :goto_0
    if-ge p2, v0, :cond_6

    .line 10
    .line 11
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Lka/a;

    .line 16
    .line 17
    iget v2, v1, Lka/a;->a:I

    .line 18
    .line 19
    const/16 v3, 0x8

    .line 20
    .line 21
    if-ne v2, v3, :cond_2

    .line 22
    .line 23
    iget v2, v1, Lka/a;->b:I

    .line 24
    .line 25
    if-ne v2, p1, :cond_0

    .line 26
    .line 27
    iget p1, v1, Lka/a;->c:I

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    if-ge v2, p1, :cond_1

    .line 31
    .line 32
    add-int/lit8 p1, p1, -0x1

    .line 33
    .line 34
    :cond_1
    iget v1, v1, Lka/a;->c:I

    .line 35
    .line 36
    if-gt v1, p1, :cond_5

    .line 37
    .line 38
    add-int/lit8 p1, p1, 0x1

    .line 39
    .line 40
    goto :goto_1

    .line 41
    :cond_2
    iget v3, v1, Lka/a;->b:I

    .line 42
    .line 43
    if-gt v3, p1, :cond_5

    .line 44
    .line 45
    const/4 v4, 0x2

    .line 46
    if-ne v2, v4, :cond_4

    .line 47
    .line 48
    iget v1, v1, Lka/a;->c:I

    .line 49
    .line 50
    add-int/2addr v3, v1

    .line 51
    if-ge p1, v3, :cond_3

    .line 52
    .line 53
    const/4 p0, -0x1

    .line 54
    return p0

    .line 55
    :cond_3
    sub-int/2addr p1, v1

    .line 56
    goto :goto_1

    .line 57
    :cond_4
    const/4 v3, 0x1

    .line 58
    if-ne v2, v3, :cond_5

    .line 59
    .line 60
    iget v1, v1, Lka/a;->c:I

    .line 61
    .line 62
    add-int/2addr p1, v1

    .line 63
    :cond_5
    :goto_1
    add-int/lit8 p2, p2, 0x1

    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_6
    return p1
.end method

.method public u(Luw/b;)Lww/d;
    .locals 4

    .line 1
    const-string v0, "Reusing Locale Cache for: "

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/lifecycle/c1;->h:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Ljava/util/concurrent/locks/ReentrantReadWriteLock;

    .line 6
    .line 7
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock;->readLock()Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;->lock()V

    .line 12
    .line 13
    .line 14
    :try_start_0
    iget-object v2, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v2, Llx0/l;

    .line 17
    .line 18
    iget-object v2, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 19
    .line 20
    invoke-virtual {p1}, Luw/b;->b()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-nez v2, :cond_0

    .line 29
    .line 30
    sget-object v0, Lvy0/p0;->a:Lcz0/e;

    .line 31
    .line 32
    sget-object v0, Lcz0/d;->e:Lcz0/d;

    .line 33
    .line 34
    new-instance v2, Lww/g;

    .line 35
    .line 36
    const/4 v3, 0x0

    .line 37
    invoke-direct {v2, p1, p0, v3}, Lww/g;-><init>(Luw/b;Landroidx/lifecycle/c1;Lkotlin/coroutines/Continuation;)V

    .line 38
    .line 39
    .line 40
    invoke-static {v0, v2}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    goto :goto_1

    .line 46
    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 47
    .line 48
    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-static {p1}, Llp/td;->a(Luw/b;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-static {p1}, Let/d;->c(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    :goto_0
    iget-object p0, p0, Landroidx/lifecycle/c1;->i:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast p0, Llx0/l;

    .line 68
    .line 69
    iget-object p0, p0, Llx0/l;->e:Ljava/lang/Object;

    .line 70
    .line 71
    const-string p1, "null cannot be cast to non-null type com.phrase.android.sdk.repo.PhraseData"

    .line 72
    .line 73
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    check-cast p0, Lww/d;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 77
    .line 78
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;->unlock()V

    .line 79
    .line 80
    .line 81
    return-object p0

    .line 82
    :goto_1
    invoke-virtual {v1}, Ljava/util/concurrent/locks/ReentrantReadWriteLock$ReadLock;->unlock()V

    .line 83
    .line 84
    .line 85
    throw p0
.end method

.method public v(IZ)F
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/text/Layout;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0, v0}, Landroid/text/Layout;->getLineEnd(I)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-le p1, v0, :cond_0

    .line 14
    .line 15
    move p1, v0

    .line 16
    :cond_0
    if-eqz p2, :cond_1

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Landroid/text/Layout;->getPrimaryHorizontal(I)F

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    return p0

    .line 23
    :cond_1
    invoke-virtual {p0, p1}, Landroid/text/Layout;->getSecondaryHorizontal(I)F

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0
.end method

.method public w()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "androidx.lifecycle.c1"

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Landroid/content/Context;

    .line 6
    .line 7
    const-string v1, "Could not get fingerprint hash for package: "

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    :try_start_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v3

    .line 14
    invoke-static {p0, v3}, Lto/b;->c(Landroid/content/Context;Ljava/lang/String;)[B

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    if-nez v3, :cond_0

    .line 19
    .line 20
    new-instance v3, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    invoke-direct {v3, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 37
    .line 38
    .line 39
    return-object v2

    .line 40
    :catch_0
    move-exception v1

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-static {v3}, Lto/b;->a([B)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    .line 46
    return-object p0

    .line 47
    :goto_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 48
    .line 49
    const-string v4, "No such package: "

    .line 50
    .line 51
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-static {v0, p0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 66
    .line 67
    .line 68
    return-object v2
.end method

.method public x(IZZ)F
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    move/from16 v2, p3

    .line 6
    .line 7
    iget-object v3, v0, Landroidx/lifecycle/c1;->e:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Landroid/text/Layout;

    .line 10
    .line 11
    if-nez v2, :cond_0

    .line 12
    .line 13
    invoke-virtual/range {p0 .. p2}, Landroidx/lifecycle/c1;->v(IZ)F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    return v0

    .line 18
    :cond_0
    invoke-static {v3, v1, v2}, Lh4/g;->d(Landroid/text/Layout;IZ)I

    .line 19
    .line 20
    .line 21
    move-result v4

    .line 22
    invoke-virtual {v3, v4}, Landroid/text/Layout;->getLineStart(I)I

    .line 23
    .line 24
    .line 25
    move-result v5

    .line 26
    invoke-virtual {v3, v4}, Landroid/text/Layout;->getLineEnd(I)I

    .line 27
    .line 28
    .line 29
    move-result v6

    .line 30
    if-eq v1, v5, :cond_1

    .line 31
    .line 32
    if-eq v1, v6, :cond_1

    .line 33
    .line 34
    invoke-virtual/range {p0 .. p2}, Landroidx/lifecycle/c1;->v(IZ)F

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    return v0

    .line 39
    :cond_1
    if-eqz v1, :cond_22

    .line 40
    .line 41
    invoke-virtual {v3}, Landroid/text/Layout;->getText()Ljava/lang/CharSequence;

    .line 42
    .line 43
    .line 44
    move-result-object v7

    .line 45
    invoke-interface {v7}, Ljava/lang/CharSequence;->length()I

    .line 46
    .line 47
    .line 48
    move-result v7

    .line 49
    if-ne v1, v7, :cond_2

    .line 50
    .line 51
    goto/16 :goto_11

    .line 52
    .line 53
    :cond_2
    invoke-virtual {v0, v1, v2}, Landroidx/lifecycle/c1;->y(IZ)I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    invoke-virtual {v0, v2}, Landroidx/lifecycle/c1;->z(I)I

    .line 58
    .line 59
    .line 60
    move-result v7

    .line 61
    invoke-virtual {v3, v7}, Landroid/text/Layout;->getLineForOffset(I)I

    .line 62
    .line 63
    .line 64
    move-result v7

    .line 65
    invoke-virtual {v3, v7}, Landroid/text/Layout;->getParagraphDirection(I)I

    .line 66
    .line 67
    .line 68
    move-result v7

    .line 69
    const/4 v8, -0x1

    .line 70
    const/4 v10, 0x1

    .line 71
    if-ne v7, v8, :cond_3

    .line 72
    .line 73
    move v7, v10

    .line 74
    goto :goto_0

    .line 75
    :cond_3
    const/4 v7, 0x0

    .line 76
    :goto_0
    invoke-virtual {v0, v6, v5}, Landroidx/lifecycle/c1;->B(II)I

    .line 77
    .line 78
    .line 79
    move-result v6

    .line 80
    invoke-virtual {v0, v2}, Landroidx/lifecycle/c1;->z(I)I

    .line 81
    .line 82
    .line 83
    move-result v11

    .line 84
    sub-int v12, v5, v11

    .line 85
    .line 86
    sub-int v11, v6, v11

    .line 87
    .line 88
    invoke-virtual {v0, v2}, Landroidx/lifecycle/c1;->g(I)Ljava/text/Bidi;

    .line 89
    .line 90
    .line 91
    move-result-object v2

    .line 92
    if-eqz v2, :cond_4

    .line 93
    .line 94
    invoke-virtual {v2, v12, v11}, Ljava/text/Bidi;->createLineBidi(II)Ljava/text/Bidi;

    .line 95
    .line 96
    .line 97
    move-result-object v2

    .line 98
    goto :goto_1

    .line 99
    :cond_4
    const/4 v2, 0x0

    .line 100
    :goto_1
    if-eqz v2, :cond_5

    .line 101
    .line 102
    invoke-virtual {v2}, Ljava/text/Bidi;->getRunCount()I

    .line 103
    .line 104
    .line 105
    move-result v11

    .line 106
    if-ne v11, v10, :cond_6

    .line 107
    .line 108
    :cond_5
    const/4 v13, 0x0

    .line 109
    goto/16 :goto_e

    .line 110
    .line 111
    :cond_6
    invoke-virtual {v2}, Ljava/text/Bidi;->getRunCount()I

    .line 112
    .line 113
    .line 114
    move-result v11

    .line 115
    new-array v12, v11, [Lh4/e;

    .line 116
    .line 117
    const/4 v13, 0x0

    .line 118
    :goto_2
    if-ge v13, v11, :cond_8

    .line 119
    .line 120
    new-instance v14, Lh4/e;

    .line 121
    .line 122
    invoke-virtual {v2, v13}, Ljava/text/Bidi;->getRunStart(I)I

    .line 123
    .line 124
    .line 125
    move-result v15

    .line 126
    add-int/2addr v15, v5

    .line 127
    invoke-virtual {v2, v13}, Ljava/text/Bidi;->getRunLimit(I)I

    .line 128
    .line 129
    .line 130
    move-result v16

    .line 131
    add-int v8, v16, v5

    .line 132
    .line 133
    invoke-virtual {v2, v13}, Ljava/text/Bidi;->getRunLevel(I)I

    .line 134
    .line 135
    .line 136
    move-result v16

    .line 137
    rem-int/lit8 v9, v16, 0x2

    .line 138
    .line 139
    if-ne v9, v10, :cond_7

    .line 140
    .line 141
    move v9, v10

    .line 142
    goto :goto_3

    .line 143
    :cond_7
    const/4 v9, 0x0

    .line 144
    :goto_3
    invoke-direct {v14, v15, v8, v9}, Lh4/e;-><init>(IIZ)V

    .line 145
    .line 146
    .line 147
    aput-object v14, v12, v13

    .line 148
    .line 149
    add-int/lit8 v13, v13, 0x1

    .line 150
    .line 151
    const/4 v8, -0x1

    .line 152
    goto :goto_2

    .line 153
    :cond_8
    invoke-virtual {v2}, Ljava/text/Bidi;->getRunCount()I

    .line 154
    .line 155
    .line 156
    move-result v8

    .line 157
    new-array v9, v8, [B

    .line 158
    .line 159
    const/4 v13, 0x0

    .line 160
    :goto_4
    if-ge v13, v8, :cond_9

    .line 161
    .line 162
    invoke-virtual {v2, v13}, Ljava/text/Bidi;->getRunLevel(I)I

    .line 163
    .line 164
    .line 165
    move-result v14

    .line 166
    int-to-byte v14, v14

    .line 167
    aput-byte v14, v9, v13

    .line 168
    .line 169
    add-int/lit8 v13, v13, 0x1

    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_9
    const/4 v13, 0x0

    .line 173
    invoke-static {v9, v13, v12, v13, v11}, Ljava/text/Bidi;->reorderVisually([BI[Ljava/lang/Object;II)V

    .line 174
    .line 175
    .line 176
    if-ne v1, v5, :cond_12

    .line 177
    .line 178
    move v0, v13

    .line 179
    :goto_5
    if-ge v0, v11, :cond_b

    .line 180
    .line 181
    aget-object v2, v12, v0

    .line 182
    .line 183
    iget v2, v2, Lh4/e;->a:I

    .line 184
    .line 185
    if-ne v2, v1, :cond_a

    .line 186
    .line 187
    move v8, v0

    .line 188
    goto :goto_6

    .line 189
    :cond_a
    add-int/lit8 v0, v0, 0x1

    .line 190
    .line 191
    goto :goto_5

    .line 192
    :cond_b
    const/4 v8, -0x1

    .line 193
    :goto_6
    aget-object v0, v12, v8

    .line 194
    .line 195
    if-nez p2, :cond_d

    .line 196
    .line 197
    iget-boolean v0, v0, Lh4/e;->c:Z

    .line 198
    .line 199
    if-ne v7, v0, :cond_c

    .line 200
    .line 201
    goto :goto_7

    .line 202
    :cond_c
    move v9, v7

    .line 203
    goto :goto_8

    .line 204
    :cond_d
    :goto_7
    if-nez v7, :cond_e

    .line 205
    .line 206
    move v9, v10

    .line 207
    goto :goto_8

    .line 208
    :cond_e
    move v9, v13

    .line 209
    :goto_8
    if-nez v8, :cond_f

    .line 210
    .line 211
    if-eqz v9, :cond_f

    .line 212
    .line 213
    invoke-virtual {v3, v4}, Landroid/text/Layout;->getLineLeft(I)F

    .line 214
    .line 215
    .line 216
    move-result v0

    .line 217
    return v0

    .line 218
    :cond_f
    sub-int/2addr v11, v10

    .line 219
    if-ne v8, v11, :cond_10

    .line 220
    .line 221
    if-nez v9, :cond_10

    .line 222
    .line 223
    invoke-virtual {v3, v4}, Landroid/text/Layout;->getLineRight(I)F

    .line 224
    .line 225
    .line 226
    move-result v0

    .line 227
    return v0

    .line 228
    :cond_10
    if-eqz v9, :cond_11

    .line 229
    .line 230
    sub-int/2addr v8, v10

    .line 231
    aget-object v0, v12, v8

    .line 232
    .line 233
    iget v0, v0, Lh4/e;->a:I

    .line 234
    .line 235
    invoke-virtual {v3, v0}, Landroid/text/Layout;->getPrimaryHorizontal(I)F

    .line 236
    .line 237
    .line 238
    move-result v0

    .line 239
    return v0

    .line 240
    :cond_11
    add-int/2addr v8, v10

    .line 241
    aget-object v0, v12, v8

    .line 242
    .line 243
    iget v0, v0, Lh4/e;->a:I

    .line 244
    .line 245
    invoke-virtual {v3, v0}, Landroid/text/Layout;->getPrimaryHorizontal(I)F

    .line 246
    .line 247
    .line 248
    move-result v0

    .line 249
    return v0

    .line 250
    :cond_12
    if-le v1, v6, :cond_13

    .line 251
    .line 252
    invoke-virtual {v0, v1, v5}, Landroidx/lifecycle/c1;->B(II)I

    .line 253
    .line 254
    .line 255
    move-result v0

    .line 256
    goto :goto_9

    .line 257
    :cond_13
    move v0, v1

    .line 258
    :goto_9
    move v1, v13

    .line 259
    :goto_a
    if-ge v1, v11, :cond_15

    .line 260
    .line 261
    aget-object v2, v12, v1

    .line 262
    .line 263
    iget v2, v2, Lh4/e;->b:I

    .line 264
    .line 265
    if-ne v2, v0, :cond_14

    .line 266
    .line 267
    move v8, v1

    .line 268
    goto :goto_b

    .line 269
    :cond_14
    add-int/lit8 v1, v1, 0x1

    .line 270
    .line 271
    goto :goto_a

    .line 272
    :cond_15
    const/4 v8, -0x1

    .line 273
    :goto_b
    aget-object v0, v12, v8

    .line 274
    .line 275
    if-nez p2, :cond_18

    .line 276
    .line 277
    iget-boolean v0, v0, Lh4/e;->c:Z

    .line 278
    .line 279
    if-ne v7, v0, :cond_16

    .line 280
    .line 281
    goto :goto_c

    .line 282
    :cond_16
    if-nez v7, :cond_17

    .line 283
    .line 284
    move v9, v10

    .line 285
    goto :goto_d

    .line 286
    :cond_17
    move v9, v13

    .line 287
    goto :goto_d

    .line 288
    :cond_18
    :goto_c
    move v9, v7

    .line 289
    :goto_d
    if-nez v8, :cond_19

    .line 290
    .line 291
    if-eqz v9, :cond_19

    .line 292
    .line 293
    invoke-virtual {v3, v4}, Landroid/text/Layout;->getLineLeft(I)F

    .line 294
    .line 295
    .line 296
    move-result v0

    .line 297
    return v0

    .line 298
    :cond_19
    sub-int/2addr v11, v10

    .line 299
    if-ne v8, v11, :cond_1a

    .line 300
    .line 301
    if-nez v9, :cond_1a

    .line 302
    .line 303
    invoke-virtual {v3, v4}, Landroid/text/Layout;->getLineRight(I)F

    .line 304
    .line 305
    .line 306
    move-result v0

    .line 307
    return v0

    .line 308
    :cond_1a
    if-eqz v9, :cond_1b

    .line 309
    .line 310
    sub-int/2addr v8, v10

    .line 311
    aget-object v0, v12, v8

    .line 312
    .line 313
    iget v0, v0, Lh4/e;->b:I

    .line 314
    .line 315
    invoke-virtual {v3, v0}, Landroid/text/Layout;->getPrimaryHorizontal(I)F

    .line 316
    .line 317
    .line 318
    move-result v0

    .line 319
    return v0

    .line 320
    :cond_1b
    add-int/2addr v8, v10

    .line 321
    aget-object v0, v12, v8

    .line 322
    .line 323
    iget v0, v0, Lh4/e;->b:I

    .line 324
    .line 325
    invoke-virtual {v3, v0}, Landroid/text/Layout;->getPrimaryHorizontal(I)F

    .line 326
    .line 327
    .line 328
    move-result v0

    .line 329
    return v0

    .line 330
    :goto_e
    invoke-virtual {v3, v5}, Landroid/text/Layout;->isRtlCharAt(I)Z

    .line 331
    .line 332
    .line 333
    move-result v0

    .line 334
    if-nez p2, :cond_1c

    .line 335
    .line 336
    if-ne v7, v0, :cond_1e

    .line 337
    .line 338
    :cond_1c
    if-nez v7, :cond_1d

    .line 339
    .line 340
    move v7, v10

    .line 341
    goto :goto_f

    .line 342
    :cond_1d
    move v7, v13

    .line 343
    :cond_1e
    :goto_f
    if-ne v1, v5, :cond_1f

    .line 344
    .line 345
    move v9, v7

    .line 346
    goto :goto_10

    .line 347
    :cond_1f
    if-nez v7, :cond_20

    .line 348
    .line 349
    move v9, v10

    .line 350
    goto :goto_10

    .line 351
    :cond_20
    move v9, v13

    .line 352
    :goto_10
    if-eqz v9, :cond_21

    .line 353
    .line 354
    invoke-virtual {v3, v4}, Landroid/text/Layout;->getLineLeft(I)F

    .line 355
    .line 356
    .line 357
    move-result v0

    .line 358
    return v0

    .line 359
    :cond_21
    invoke-virtual {v3, v4}, Landroid/text/Layout;->getLineRight(I)F

    .line 360
    .line 361
    .line 362
    move-result v0

    .line 363
    return v0

    .line 364
    :cond_22
    :goto_11
    invoke-virtual/range {p0 .. p2}, Landroidx/lifecycle/c1;->v(IZ)F

    .line 365
    .line 366
    .line 367
    move-result v0

    .line 368
    return v0
.end method

.method public y(IZ)I
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {p0, v0}, Ljp/k1;->c(Ljava/util/ArrayList;Ljava/lang/Comparable;)I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-gez v0, :cond_0

    .line 14
    .line 15
    add-int/lit8 v0, v0, 0x1

    .line 16
    .line 17
    neg-int v0, v0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 20
    .line 21
    :goto_0
    if-eqz p2, :cond_1

    .line 22
    .line 23
    if-lez v0, :cond_1

    .line 24
    .line 25
    add-int/lit8 p2, v0, -0x1

    .line 26
    .line 27
    invoke-virtual {p0, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Ljava/lang/Number;

    .line 32
    .line 33
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-ne p1, p0, :cond_1

    .line 38
    .line 39
    return p2

    .line 40
    :cond_1
    return v0
.end method

.method public z(I)I
    .locals 0

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x0

    .line 4
    return p0

    .line 5
    :cond_0
    iget-object p0, p0, Landroidx/lifecycle/c1;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/util/ArrayList;

    .line 8
    .line 9
    add-int/lit8 p1, p1, -0x1

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Number;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0
.end method
