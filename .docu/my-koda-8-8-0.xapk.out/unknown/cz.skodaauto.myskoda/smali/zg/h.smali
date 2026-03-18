.class public final Lzg/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lzg/h;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lzg/e;

.field public static final w:[Llx0/i;


# instance fields
.field public final d:Ljava/util/List;

.field public final e:Lzg/g;

.field public final f:Ljava/lang/String;

.field public final g:Lzg/q;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Ljava/lang/String;

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/Boolean;

.field public final q:Lzg/h2;

.field public final r:Z

.field public final s:Ljava/lang/String;

.field public final t:Lzg/q1;

.field public final u:Lzg/x1;

.field public v:Z


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lzg/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lzg/h;->Companion:Lzg/e;

    .line 7
    .line 8
    new-instance v0, Ltt/f;

    .line 9
    .line 10
    const/16 v1, 0x18

    .line 11
    .line 12
    invoke-direct {v0, v1}, Ltt/f;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lzg/h;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 16
    .line 17
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 18
    .line 19
    new-instance v1, Lz81/g;

    .line 20
    .line 21
    const/16 v2, 0xc

    .line 22
    .line 23
    invoke-direct {v1, v2}, Lz81/g;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    new-instance v3, Lz81/g;

    .line 31
    .line 32
    const/16 v4, 0xd

    .line 33
    .line 34
    invoke-direct {v3, v4}, Lz81/g;-><init>(I)V

    .line 35
    .line 36
    .line 37
    invoke-static {v0, v3}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    const/16 v3, 0x13

    .line 42
    .line 43
    new-array v3, v3, [Llx0/i;

    .line 44
    .line 45
    const/4 v5, 0x0

    .line 46
    aput-object v1, v3, v5

    .line 47
    .line 48
    const/4 v1, 0x1

    .line 49
    aput-object v0, v3, v1

    .line 50
    .line 51
    const/4 v0, 0x2

    .line 52
    const/4 v1, 0x0

    .line 53
    aput-object v1, v3, v0

    .line 54
    .line 55
    const/4 v0, 0x3

    .line 56
    aput-object v1, v3, v0

    .line 57
    .line 58
    const/4 v0, 0x4

    .line 59
    aput-object v1, v3, v0

    .line 60
    .line 61
    const/4 v0, 0x5

    .line 62
    aput-object v1, v3, v0

    .line 63
    .line 64
    const/4 v0, 0x6

    .line 65
    aput-object v1, v3, v0

    .line 66
    .line 67
    const/4 v0, 0x7

    .line 68
    aput-object v1, v3, v0

    .line 69
    .line 70
    const/16 v0, 0x8

    .line 71
    .line 72
    aput-object v1, v3, v0

    .line 73
    .line 74
    const/16 v0, 0x9

    .line 75
    .line 76
    aput-object v1, v3, v0

    .line 77
    .line 78
    const/16 v0, 0xa

    .line 79
    .line 80
    aput-object v1, v3, v0

    .line 81
    .line 82
    const/16 v0, 0xb

    .line 83
    .line 84
    aput-object v1, v3, v0

    .line 85
    .line 86
    aput-object v1, v3, v2

    .line 87
    .line 88
    aput-object v1, v3, v4

    .line 89
    .line 90
    const/16 v0, 0xe

    .line 91
    .line 92
    aput-object v1, v3, v0

    .line 93
    .line 94
    const/16 v0, 0xf

    .line 95
    .line 96
    aput-object v1, v3, v0

    .line 97
    .line 98
    const/16 v0, 0x10

    .line 99
    .line 100
    aput-object v1, v3, v0

    .line 101
    .line 102
    const/16 v0, 0x11

    .line 103
    .line 104
    aput-object v1, v3, v0

    .line 105
    .line 106
    const/16 v0, 0x12

    .line 107
    .line 108
    aput-object v1, v3, v0

    .line 109
    .line 110
    sput-object v3, Lzg/h;->w:[Llx0/i;

    .line 111
    .line 112
    return-void
.end method

.method public synthetic constructor <init>(ILjava/util/List;Lzg/g;Ljava/lang/String;Lzg/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lzg/h2;ZLjava/lang/String;Lzg/q1;Lzg/x1;Z)V
    .locals 3

    and-int/lit16 v0, p1, 0x6037

    const/4 v1, 0x0

    const/16 v2, 0x6037

    if-ne v2, v0, :cond_c

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lzg/h;->d:Ljava/util/List;

    iput-object p3, p0, Lzg/h;->e:Lzg/g;

    iput-object p4, p0, Lzg/h;->f:Ljava/lang/String;

    and-int/lit8 p2, p1, 0x8

    if-nez p2, :cond_0

    iput-object v1, p0, Lzg/h;->g:Lzg/q;

    goto :goto_0

    :cond_0
    iput-object p5, p0, Lzg/h;->g:Lzg/q;

    :goto_0
    iput-object p6, p0, Lzg/h;->h:Ljava/lang/String;

    iput-object p7, p0, Lzg/h;->i:Ljava/lang/String;

    and-int/lit8 p2, p1, 0x40

    if-nez p2, :cond_1

    iput-object v1, p0, Lzg/h;->j:Ljava/lang/String;

    goto :goto_1

    :cond_1
    iput-object p8, p0, Lzg/h;->j:Ljava/lang/String;

    :goto_1
    and-int/lit16 p2, p1, 0x80

    if-nez p2, :cond_2

    iput-object v1, p0, Lzg/h;->k:Ljava/lang/String;

    goto :goto_2

    :cond_2
    iput-object p9, p0, Lzg/h;->k:Ljava/lang/String;

    :goto_2
    and-int/lit16 p2, p1, 0x100

    if-nez p2, :cond_3

    iput-object v1, p0, Lzg/h;->l:Ljava/lang/String;

    goto :goto_3

    :cond_3
    iput-object p10, p0, Lzg/h;->l:Ljava/lang/String;

    :goto_3
    and-int/lit16 p2, p1, 0x200

    if-nez p2, :cond_4

    iput-object v1, p0, Lzg/h;->m:Ljava/lang/String;

    goto :goto_4

    :cond_4
    iput-object p11, p0, Lzg/h;->m:Ljava/lang/String;

    :goto_4
    and-int/lit16 p2, p1, 0x400

    if-nez p2, :cond_5

    iput-object v1, p0, Lzg/h;->n:Ljava/lang/String;

    goto :goto_5

    :cond_5
    iput-object p12, p0, Lzg/h;->n:Ljava/lang/String;

    :goto_5
    and-int/lit16 p2, p1, 0x800

    if-nez p2, :cond_6

    iput-object v1, p0, Lzg/h;->o:Ljava/lang/String;

    goto :goto_6

    :cond_6
    move-object/from16 p2, p13

    iput-object p2, p0, Lzg/h;->o:Ljava/lang/String;

    :goto_6
    and-int/lit16 p2, p1, 0x1000

    if-nez p2, :cond_7

    iput-object v1, p0, Lzg/h;->p:Ljava/lang/Boolean;

    :goto_7
    move-object/from16 p2, p15

    goto :goto_8

    :cond_7
    move-object/from16 p2, p14

    iput-object p2, p0, Lzg/h;->p:Ljava/lang/Boolean;

    goto :goto_7

    :goto_8
    iput-object p2, p0, Lzg/h;->q:Lzg/h2;

    move/from16 p2, p16

    iput-boolean p2, p0, Lzg/h;->r:Z

    const p2, 0x8000

    and-int/2addr p2, p1

    if-nez p2, :cond_8

    iput-object v1, p0, Lzg/h;->s:Ljava/lang/String;

    goto :goto_9

    :cond_8
    move-object/from16 p2, p17

    iput-object p2, p0, Lzg/h;->s:Ljava/lang/String;

    :goto_9
    const/high16 p2, 0x10000

    and-int/2addr p2, p1

    if-nez p2, :cond_9

    iput-object v1, p0, Lzg/h;->t:Lzg/q1;

    goto :goto_a

    :cond_9
    move-object/from16 p2, p18

    iput-object p2, p0, Lzg/h;->t:Lzg/q1;

    :goto_a
    const/high16 p2, 0x20000

    and-int/2addr p2, p1

    if-nez p2, :cond_a

    iput-object v1, p0, Lzg/h;->u:Lzg/x1;

    goto :goto_b

    :cond_a
    move-object/from16 p2, p19

    iput-object p2, p0, Lzg/h;->u:Lzg/x1;

    :goto_b
    const/high16 p2, 0x40000

    and-int/2addr p1, p2

    if-nez p1, :cond_b

    const/4 p1, 0x0

    :goto_c
    iput-boolean p1, p0, Lzg/h;->v:Z

    return-void

    :cond_b
    move/from16 p1, p20

    goto :goto_c

    :cond_c
    sget-object p0, Lzg/d;->a:Lzg/d;

    invoke-virtual {p0}, Lzg/d;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v2, p0}, Luz0/b1;->l(IILsz0/g;)V

    throw v1
.end method

.method public constructor <init>(Ljava/util/List;Lzg/g;Ljava/lang/String;Lzg/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lzg/h2;ZLjava/lang/String;Lzg/q1;Lzg/x1;Z)V
    .locals 2

    move-object/from16 v0, p14

    const-string v1, "imageIds"

    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "status"

    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "localizedStatus"

    invoke-static {p3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "name"

    invoke-static {p5, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "id"

    invoke-static {p6, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "wallboxAppHyperlink"

    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lzg/h;->d:Ljava/util/List;

    .line 4
    iput-object p2, p0, Lzg/h;->e:Lzg/g;

    .line 5
    iput-object p3, p0, Lzg/h;->f:Ljava/lang/String;

    .line 6
    iput-object p4, p0, Lzg/h;->g:Lzg/q;

    .line 7
    iput-object p5, p0, Lzg/h;->h:Ljava/lang/String;

    .line 8
    iput-object p6, p0, Lzg/h;->i:Ljava/lang/String;

    .line 9
    iput-object p7, p0, Lzg/h;->j:Ljava/lang/String;

    .line 10
    iput-object p8, p0, Lzg/h;->k:Ljava/lang/String;

    .line 11
    iput-object p9, p0, Lzg/h;->l:Ljava/lang/String;

    .line 12
    iput-object p10, p0, Lzg/h;->m:Ljava/lang/String;

    .line 13
    iput-object p11, p0, Lzg/h;->n:Ljava/lang/String;

    .line 14
    iput-object p12, p0, Lzg/h;->o:Ljava/lang/String;

    .line 15
    iput-object p13, p0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 16
    iput-object v0, p0, Lzg/h;->q:Lzg/h2;

    move/from16 p1, p15

    .line 17
    iput-boolean p1, p0, Lzg/h;->r:Z

    move-object/from16 p1, p16

    .line 18
    iput-object p1, p0, Lzg/h;->s:Ljava/lang/String;

    move-object/from16 p1, p17

    .line 19
    iput-object p1, p0, Lzg/h;->t:Lzg/q1;

    move-object/from16 p1, p18

    .line 20
    iput-object p1, p0, Lzg/h;->u:Lzg/x1;

    move/from16 p1, p19

    .line 21
    iput-boolean p1, p0, Lzg/h;->v:Z

    return-void
.end method

.method public static a(Lzg/h;Z)Lzg/h;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lzg/h;->d:Ljava/util/List;

    .line 4
    .line 5
    iget-object v2, v0, Lzg/h;->e:Lzg/g;

    .line 6
    .line 7
    iget-object v3, v0, Lzg/h;->f:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, v0, Lzg/h;->g:Lzg/q;

    .line 10
    .line 11
    iget-object v5, v0, Lzg/h;->h:Ljava/lang/String;

    .line 12
    .line 13
    iget-object v6, v0, Lzg/h;->i:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v7, v0, Lzg/h;->j:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v8, v0, Lzg/h;->k:Ljava/lang/String;

    .line 18
    .line 19
    iget-object v9, v0, Lzg/h;->l:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v10, v0, Lzg/h;->m:Ljava/lang/String;

    .line 22
    .line 23
    iget-object v11, v0, Lzg/h;->n:Ljava/lang/String;

    .line 24
    .line 25
    iget-object v12, v0, Lzg/h;->o:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v13, v0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 28
    .line 29
    iget-object v14, v0, Lzg/h;->q:Lzg/h2;

    .line 30
    .line 31
    iget-boolean v15, v0, Lzg/h;->r:Z

    .line 32
    .line 33
    move-object/from16 v16, v4

    .line 34
    .line 35
    iget-object v4, v0, Lzg/h;->s:Ljava/lang/String;

    .line 36
    .line 37
    move-object/from16 v17, v4

    .line 38
    .line 39
    iget-object v4, v0, Lzg/h;->t:Lzg/q1;

    .line 40
    .line 41
    move-object/from16 v18, v4

    .line 42
    .line 43
    iget-object v4, v0, Lzg/h;->u:Lzg/x1;

    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    const-string v0, "imageIds"

    .line 49
    .line 50
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    const-string v0, "status"

    .line 54
    .line 55
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    const-string v0, "localizedStatus"

    .line 59
    .line 60
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const-string v0, "name"

    .line 64
    .line 65
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string v0, "id"

    .line 69
    .line 70
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    const-string v0, "wallboxAppHyperlink"

    .line 74
    .line 75
    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    new-instance v0, Lzg/h;

    .line 79
    .line 80
    move-object/from16 v19, v18

    .line 81
    .line 82
    move-object/from16 v18, v4

    .line 83
    .line 84
    move-object/from16 v4, v16

    .line 85
    .line 86
    move-object/from16 v16, v17

    .line 87
    .line 88
    move-object/from16 v17, v19

    .line 89
    .line 90
    move/from16 v19, p1

    .line 91
    .line 92
    invoke-direct/range {v0 .. v19}, Lzg/h;-><init>(Ljava/util/List;Lzg/g;Ljava/lang/String;Lzg/q;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Lzg/h2;ZLjava/lang/String;Lzg/q1;Lzg/x1;Z)V

    .line 93
    .line 94
    .line 95
    return-object v0
.end method


# virtual methods
.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lzg/h;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lzg/h;

    .line 12
    .line 13
    iget-object v1, p0, Lzg/h;->d:Ljava/util/List;

    .line 14
    .line 15
    iget-object v3, p1, Lzg/h;->d:Ljava/util/List;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lzg/h;->e:Lzg/g;

    .line 25
    .line 26
    iget-object v3, p1, Lzg/h;->e:Lzg/g;

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lzg/h;->f:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lzg/h;->f:Ljava/lang/String;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object v1, p0, Lzg/h;->g:Lzg/q;

    .line 43
    .line 44
    iget-object v3, p1, Lzg/h;->g:Lzg/q;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lzg/h;->h:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lzg/h;->h:Ljava/lang/String;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget-object v1, p0, Lzg/h;->i:Ljava/lang/String;

    .line 65
    .line 66
    iget-object v3, p1, Lzg/h;->i:Ljava/lang/String;

    .line 67
    .line 68
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result v1

    .line 72
    if-nez v1, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-object v1, p0, Lzg/h;->j:Ljava/lang/String;

    .line 76
    .line 77
    iget-object v3, p1, Lzg/h;->j:Ljava/lang/String;

    .line 78
    .line 79
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    if-nez v1, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-object v1, p0, Lzg/h;->k:Ljava/lang/String;

    .line 87
    .line 88
    iget-object v3, p1, Lzg/h;->k:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    if-nez v1, :cond_9

    .line 95
    .line 96
    return v2

    .line 97
    :cond_9
    iget-object v1, p0, Lzg/h;->l:Ljava/lang/String;

    .line 98
    .line 99
    iget-object v3, p1, Lzg/h;->l:Ljava/lang/String;

    .line 100
    .line 101
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    if-nez v1, :cond_a

    .line 106
    .line 107
    return v2

    .line 108
    :cond_a
    iget-object v1, p0, Lzg/h;->m:Ljava/lang/String;

    .line 109
    .line 110
    iget-object v3, p1, Lzg/h;->m:Ljava/lang/String;

    .line 111
    .line 112
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result v1

    .line 116
    if-nez v1, :cond_b

    .line 117
    .line 118
    return v2

    .line 119
    :cond_b
    iget-object v1, p0, Lzg/h;->n:Ljava/lang/String;

    .line 120
    .line 121
    iget-object v3, p1, Lzg/h;->n:Ljava/lang/String;

    .line 122
    .line 123
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    if-nez v1, :cond_c

    .line 128
    .line 129
    return v2

    .line 130
    :cond_c
    iget-object v1, p0, Lzg/h;->o:Ljava/lang/String;

    .line 131
    .line 132
    iget-object v3, p1, Lzg/h;->o:Ljava/lang/String;

    .line 133
    .line 134
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    if-nez v1, :cond_d

    .line 139
    .line 140
    return v2

    .line 141
    :cond_d
    iget-object v1, p0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 142
    .line 143
    iget-object v3, p1, Lzg/h;->p:Ljava/lang/Boolean;

    .line 144
    .line 145
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    if-nez v1, :cond_e

    .line 150
    .line 151
    return v2

    .line 152
    :cond_e
    iget-object v1, p0, Lzg/h;->q:Lzg/h2;

    .line 153
    .line 154
    iget-object v3, p1, Lzg/h;->q:Lzg/h2;

    .line 155
    .line 156
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    move-result v1

    .line 160
    if-nez v1, :cond_f

    .line 161
    .line 162
    return v2

    .line 163
    :cond_f
    iget-boolean v1, p0, Lzg/h;->r:Z

    .line 164
    .line 165
    iget-boolean v3, p1, Lzg/h;->r:Z

    .line 166
    .line 167
    if-eq v1, v3, :cond_10

    .line 168
    .line 169
    return v2

    .line 170
    :cond_10
    iget-object v1, p0, Lzg/h;->s:Ljava/lang/String;

    .line 171
    .line 172
    iget-object v3, p1, Lzg/h;->s:Ljava/lang/String;

    .line 173
    .line 174
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v1

    .line 178
    if-nez v1, :cond_11

    .line 179
    .line 180
    return v2

    .line 181
    :cond_11
    iget-object v1, p0, Lzg/h;->t:Lzg/q1;

    .line 182
    .line 183
    iget-object v3, p1, Lzg/h;->t:Lzg/q1;

    .line 184
    .line 185
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 186
    .line 187
    .line 188
    move-result v1

    .line 189
    if-nez v1, :cond_12

    .line 190
    .line 191
    return v2

    .line 192
    :cond_12
    iget-object v1, p0, Lzg/h;->u:Lzg/x1;

    .line 193
    .line 194
    iget-object v3, p1, Lzg/h;->u:Lzg/x1;

    .line 195
    .line 196
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    move-result v1

    .line 200
    if-nez v1, :cond_13

    .line 201
    .line 202
    return v2

    .line 203
    :cond_13
    iget-boolean p0, p0, Lzg/h;->v:Z

    .line 204
    .line 205
    iget-boolean p1, p1, Lzg/h;->v:Z

    .line 206
    .line 207
    if-eq p0, p1, :cond_14

    .line 208
    .line 209
    return v2

    .line 210
    :cond_14
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lzg/h;->d:Ljava/util/List;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lzg/h;->e:Lzg/g;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Lzg/h;->f:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    const/4 v2, 0x0

    .line 25
    iget-object v3, p0, Lzg/h;->g:Lzg/q;

    .line 26
    .line 27
    if-nez v3, :cond_0

    .line 28
    .line 29
    move v3, v2

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-virtual {v3}, Lzg/q;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    :goto_0
    add-int/2addr v0, v3

    .line 36
    mul-int/2addr v0, v1

    .line 37
    iget-object v3, p0, Lzg/h;->h:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    iget-object v3, p0, Lzg/h;->i:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    iget-object v3, p0, Lzg/h;->j:Ljava/lang/String;

    .line 50
    .line 51
    if-nez v3, :cond_1

    .line 52
    .line 53
    move v3, v2

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    :goto_1
    add-int/2addr v0, v3

    .line 60
    mul-int/2addr v0, v1

    .line 61
    iget-object v3, p0, Lzg/h;->k:Ljava/lang/String;

    .line 62
    .line 63
    if-nez v3, :cond_2

    .line 64
    .line 65
    move v3, v2

    .line 66
    goto :goto_2

    .line 67
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    :goto_2
    add-int/2addr v0, v3

    .line 72
    mul-int/2addr v0, v1

    .line 73
    iget-object v3, p0, Lzg/h;->l:Ljava/lang/String;

    .line 74
    .line 75
    if-nez v3, :cond_3

    .line 76
    .line 77
    move v3, v2

    .line 78
    goto :goto_3

    .line 79
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    :goto_3
    add-int/2addr v0, v3

    .line 84
    mul-int/2addr v0, v1

    .line 85
    iget-object v3, p0, Lzg/h;->m:Ljava/lang/String;

    .line 86
    .line 87
    if-nez v3, :cond_4

    .line 88
    .line 89
    move v3, v2

    .line 90
    goto :goto_4

    .line 91
    :cond_4
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 92
    .line 93
    .line 94
    move-result v3

    .line 95
    :goto_4
    add-int/2addr v0, v3

    .line 96
    mul-int/2addr v0, v1

    .line 97
    iget-object v3, p0, Lzg/h;->n:Ljava/lang/String;

    .line 98
    .line 99
    if-nez v3, :cond_5

    .line 100
    .line 101
    move v3, v2

    .line 102
    goto :goto_5

    .line 103
    :cond_5
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    :goto_5
    add-int/2addr v0, v3

    .line 108
    mul-int/2addr v0, v1

    .line 109
    iget-object v3, p0, Lzg/h;->o:Ljava/lang/String;

    .line 110
    .line 111
    if-nez v3, :cond_6

    .line 112
    .line 113
    move v3, v2

    .line 114
    goto :goto_6

    .line 115
    :cond_6
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 116
    .line 117
    .line 118
    move-result v3

    .line 119
    :goto_6
    add-int/2addr v0, v3

    .line 120
    mul-int/2addr v0, v1

    .line 121
    iget-object v3, p0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 122
    .line 123
    if-nez v3, :cond_7

    .line 124
    .line 125
    move v3, v2

    .line 126
    goto :goto_7

    .line 127
    :cond_7
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    :goto_7
    add-int/2addr v0, v3

    .line 132
    mul-int/2addr v0, v1

    .line 133
    iget-object v3, p0, Lzg/h;->q:Lzg/h2;

    .line 134
    .line 135
    invoke-virtual {v3}, Lzg/h2;->hashCode()I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    add-int/2addr v3, v0

    .line 140
    mul-int/2addr v3, v1

    .line 141
    iget-boolean v0, p0, Lzg/h;->r:Z

    .line 142
    .line 143
    invoke-static {v3, v1, v0}, La7/g0;->e(IIZ)I

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    iget-object v3, p0, Lzg/h;->s:Ljava/lang/String;

    .line 148
    .line 149
    if-nez v3, :cond_8

    .line 150
    .line 151
    move v3, v2

    .line 152
    goto :goto_8

    .line 153
    :cond_8
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 154
    .line 155
    .line 156
    move-result v3

    .line 157
    :goto_8
    add-int/2addr v0, v3

    .line 158
    mul-int/2addr v0, v1

    .line 159
    iget-object v3, p0, Lzg/h;->t:Lzg/q1;

    .line 160
    .line 161
    if-nez v3, :cond_9

    .line 162
    .line 163
    move v3, v2

    .line 164
    goto :goto_9

    .line 165
    :cond_9
    invoke-virtual {v3}, Lzg/q1;->hashCode()I

    .line 166
    .line 167
    .line 168
    move-result v3

    .line 169
    :goto_9
    add-int/2addr v0, v3

    .line 170
    mul-int/2addr v0, v1

    .line 171
    iget-object v3, p0, Lzg/h;->u:Lzg/x1;

    .line 172
    .line 173
    if-nez v3, :cond_a

    .line 174
    .line 175
    goto :goto_a

    .line 176
    :cond_a
    invoke-virtual {v3}, Lzg/x1;->hashCode()I

    .line 177
    .line 178
    .line 179
    move-result v2

    .line 180
    :goto_a
    add-int/2addr v0, v2

    .line 181
    mul-int/2addr v0, v1

    .line 182
    iget-boolean p0, p0, Lzg/h;->v:Z

    .line 183
    .line 184
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 185
    .line 186
    .line 187
    move-result p0

    .line 188
    add-int/2addr p0, v0

    .line 189
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-boolean v0, p0, Lzg/h;->v:Z

    .line 2
    .line 3
    new-instance v1, Ljava/lang/StringBuilder;

    .line 4
    .line 5
    const-string v2, "ChargingStation(imageIds="

    .line 6
    .line 7
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v2, p0, Lzg/h;->d:Ljava/util/List;

    .line 11
    .line 12
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v2, ", status="

    .line 16
    .line 17
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    iget-object v2, p0, Lzg/h;->e:Lzg/g;

    .line 21
    .line 22
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string v2, ", localizedStatus="

    .line 26
    .line 27
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    iget-object v2, p0, Lzg/h;->f:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v2, ", description="

    .line 36
    .line 37
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    iget-object v2, p0, Lzg/h;->g:Lzg/q;

    .line 41
    .line 42
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v2, ", name="

    .line 46
    .line 47
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v2, ", id="

    .line 51
    .line 52
    const-string v3, ", sessionID="

    .line 53
    .line 54
    iget-object v4, p0, Lzg/h;->h:Ljava/lang/String;

    .line 55
    .line 56
    iget-object v5, p0, Lzg/h;->i:Ljava/lang/String;

    .line 57
    .line 58
    invoke-static {v1, v4, v2, v5, v3}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    const-string v2, ", amountCharged="

    .line 62
    .line 63
    const-string v3, ", formattedStartDateTime="

    .line 64
    .line 65
    iget-object v4, p0, Lzg/h;->j:Ljava/lang/String;

    .line 66
    .line 67
    iget-object v5, p0, Lzg/h;->k:Ljava/lang/String;

    .line 68
    .line 69
    invoke-static {v1, v4, v2, v5, v3}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    const-string v2, ", chargingTime="

    .line 73
    .line 74
    const-string v3, ", formattedAuthentication="

    .line 75
    .line 76
    iget-object v4, p0, Lzg/h;->l:Ljava/lang/String;

    .line 77
    .line 78
    iget-object v5, p0, Lzg/h;->m:Ljava/lang/String;

    .line 79
    .line 80
    invoke-static {v1, v4, v2, v5, v3}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    const-string v2, ", formattedAddress="

    .line 84
    .line 85
    const-string v3, ", authenticationOn="

    .line 86
    .line 87
    iget-object v4, p0, Lzg/h;->n:Ljava/lang/String;

    .line 88
    .line 89
    iget-object v5, p0, Lzg/h;->o:Ljava/lang/String;

    .line 90
    .line 91
    invoke-static {v1, v4, v2, v5, v3}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    iget-object v2, p0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 95
    .line 96
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    const-string v2, ", wallboxAppHyperlink="

    .line 100
    .line 101
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    iget-object v2, p0, Lzg/h;->q:Lzg/h2;

    .line 105
    .line 106
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const-string v2, ", isAuthenticationChangeAllowed="

    .line 110
    .line 111
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    const-string v2, ", locationId="

    .line 115
    .line 116
    const-string v3, ", pvForecastCharging="

    .line 117
    .line 118
    iget-object v4, p0, Lzg/h;->s:Ljava/lang/String;

    .line 119
    .line 120
    iget-boolean v5, p0, Lzg/h;->r:Z

    .line 121
    .line 122
    invoke-static {v2, v4, v3, v1, v5}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 123
    .line 124
    .line 125
    iget-object v2, p0, Lzg/h;->t:Lzg/q1;

    .line 126
    .line 127
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    const-string v2, ", pvSurplusCharging="

    .line 131
    .line 132
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    iget-object p0, p0, Lzg/h;->u:Lzg/x1;

    .line 136
    .line 137
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    const-string p0, ", isButtonLoading="

    .line 141
    .line 142
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    const-string p0, ")"

    .line 146
    .line 147
    invoke-static {v1, v0, p0}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

    .line 1
    const-string v0, "dest"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lzg/h;->d:Ljava/util/List;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeStringList(Ljava/util/List;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lzg/h;->e:Lzg/g;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    iget-object v0, p0, Lzg/h;->f:Ljava/lang/String;

    .line 21
    .line 22
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    const/4 v0, 0x1

    .line 26
    const/4 v1, 0x0

    .line 27
    iget-object v2, p0, Lzg/h;->g:Lzg/q;

    .line 28
    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_0
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v2, p1, p2}, Lzg/q;->writeToParcel(Landroid/os/Parcel;I)V

    .line 39
    .line 40
    .line 41
    :goto_0
    iget-object v2, p0, Lzg/h;->h:Ljava/lang/String;

    .line 42
    .line 43
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    iget-object v2, p0, Lzg/h;->i:Ljava/lang/String;

    .line 47
    .line 48
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    iget-object v2, p0, Lzg/h;->j:Ljava/lang/String;

    .line 52
    .line 53
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget-object v2, p0, Lzg/h;->k:Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    iget-object v2, p0, Lzg/h;->l:Ljava/lang/String;

    .line 62
    .line 63
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    iget-object v2, p0, Lzg/h;->m:Ljava/lang/String;

    .line 67
    .line 68
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    iget-object v2, p0, Lzg/h;->n:Ljava/lang/String;

    .line 72
    .line 73
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    iget-object v2, p0, Lzg/h;->o:Ljava/lang/String;

    .line 77
    .line 78
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    iget-object v2, p0, Lzg/h;->p:Ljava/lang/Boolean;

    .line 82
    .line 83
    if-nez v2, :cond_1

    .line 84
    .line 85
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 86
    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 97
    .line 98
    .line 99
    :goto_1
    iget-object v2, p0, Lzg/h;->q:Lzg/h2;

    .line 100
    .line 101
    invoke-virtual {v2, p1, p2}, Lzg/h2;->writeToParcel(Landroid/os/Parcel;I)V

    .line 102
    .line 103
    .line 104
    iget-boolean v2, p0, Lzg/h;->r:Z

    .line 105
    .line 106
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 107
    .line 108
    .line 109
    iget-object v2, p0, Lzg/h;->s:Ljava/lang/String;

    .line 110
    .line 111
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    iget-object v2, p0, Lzg/h;->t:Lzg/q1;

    .line 115
    .line 116
    if-nez v2, :cond_2

    .line 117
    .line 118
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 119
    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_2
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v2, p1, p2}, Lzg/q1;->writeToParcel(Landroid/os/Parcel;I)V

    .line 126
    .line 127
    .line 128
    :goto_2
    iget-object v2, p0, Lzg/h;->u:Lzg/x1;

    .line 129
    .line 130
    if-nez v2, :cond_3

    .line 131
    .line 132
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 133
    .line 134
    .line 135
    goto :goto_3

    .line 136
    :cond_3
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v2, p1, p2}, Lzg/x1;->writeToParcel(Landroid/os/Parcel;I)V

    .line 140
    .line 141
    .line 142
    :goto_3
    iget-boolean p0, p0, Lzg/h;->v:Z

    .line 143
    .line 144
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 145
    .line 146
    .line 147
    return-void
.end method
