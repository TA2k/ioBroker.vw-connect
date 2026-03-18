.class public final Lhu/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lju/b;
.implements Low0/f;
.implements Li8/d;
.implements Llz0/a;
.implements Lka/e1;
.implements Lks/a;
.implements Lm/a2;
.implements Lkv/a;
.implements Lm/m;
.implements Laq/i;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(BI)V
    .locals 0

    iput p2, p0, Lhu/q;->d:I

    sparse-switch p2, :sswitch_data_0

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 19
    new-instance p1, Lwe0/b;

    const/16 p2, 0x8

    .line 20
    invoke-direct {p1, p2}, Lwe0/b;-><init>(I)V

    .line 21
    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void

    .line 22
    :sswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    new-instance p1, Landroidx/collection/u;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Landroidx/collection/u;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void

    .line 24
    :sswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    .line 25
    :sswitch_2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void

    .line 27
    :sswitch_3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 28
    new-instance p1, Ljava/util/ArrayList;

    const/16 p2, 0x20

    invoke-direct {p1, p2}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x6 -> :sswitch_3
        0x14 -> :sswitch_2
        0x1b -> :sswitch_1
        0x1d -> :sswitch_0
    .end sparse-switch
.end method

.method public constructor <init>(I)V
    .locals 1

    const/16 v0, 0x10

    iput v0, p0, Lhu/q;->d:I

    .line 37
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    new-array p1, p1, [I

    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p1

    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    const/16 v0, 0x1a

    iput v0, p0, Lhu/q;->d:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    const/4 v0, 0x0

    .line 8
    const-string v1, "core-google-shortcuts.PREF_FILE_NAME"

    invoke-virtual {p1, v1, v0}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/work/impl/WorkDatabase;)V
    .locals 1

    const/16 v0, 0x18

    iput v0, p0, Lhu/q;->d:I

    const-string v0, "workDatabase"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh6/e;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lhu/q;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iget-object p1, p1, Lh6/e;->e:Ljava/lang/Object;

    check-cast p1, Ljava/util/BitSet;

    .line 4
    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p2, p0, Lhu/q;->d:I

    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    const/4 v0, 0x5

    iput v0, p0, Lhu/q;->d:I

    .line 32
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 33
    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    move-result-object v0

    iput-object v0, p0, Lhu/q;->e:Ljava/lang/Object;

    const/4 p0, 0x0

    .line 34
    invoke-static {p1, p0}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    move-result-object p1

    .line 35
    array-length v1, p1

    invoke-virtual {v0, p1, p0, v1}, Landroid/os/Parcel;->unmarshall([BII)V

    .line 36
    invoke-virtual {v0, p0}, Landroid/os/Parcel;->setDataPosition(I)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/security/KeyStore;)V
    .locals 1

    const/16 v0, 0x19

    iput v0, p0, Lhu/q;->d:I

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 10
    invoke-virtual {p2, p1, v0}, Ljava/security/KeyStore;->getKey(Ljava/lang/String;[C)Ljava/security/Key;

    move-result-object p2

    check-cast p2, Ljavax/crypto/SecretKey;

    iput-object p2, p0, Lhu/q;->e:Ljava/lang/Object;

    if-eqz p2, :cond_0

    return-void

    .line 11
    :cond_0
    new-instance p0, Ljava/security/InvalidKeyException;

    const-string p2, "Keystore cannot load the key with ID: "

    .line 12
    invoke-static {p2, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 13
    invoke-direct {p0, p1}, Ljava/security/InvalidKeyException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Ljava/util/UUID;I[B[Ljava/util/UUID;)V
    .locals 0

    const/4 p2, 0x4

    iput p2, p0, Lhu/q;->d:I

    .line 29
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 30
    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lms/j;Ljava/lang/String;)V
    .locals 0

    const/16 p2, 0x16

    iput p2, p0, Lhu/q;->d:I

    .line 31
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lhu/q;->e:Ljava/lang/Object;

    return-void
.end method

.method public static final N(Lh6/e;Lhu/q;)Lhu/q;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lh6/e;->z()[B

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/p;->a()Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {p0, v0}, Lqr/g;->q([BLcom/google/crypto/tink/shaded/protobuf/p;)Lqr/g;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p0}, Lqr/g;->o()Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {v0}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const-string v1, "empty keyset"

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    new-instance v0, Lhu/q;

    .line 26
    .line 27
    :try_start_0
    invoke-virtual {p0}, Lqr/g;->o()Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-nez v2, :cond_0

    .line 36
    .line 37
    sget-object p0, Lcom/google/crypto/tink/shaded/protobuf/b0;->b:[B

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    new-array v3, v2, [B

    .line 41
    .line 42
    invoke-virtual {p0, v2, v3}, Lcom/google/crypto/tink/shaded/protobuf/i;->i(I[B)V

    .line 43
    .line 44
    .line 45
    move-object p0, v3

    .line 46
    :goto_0
    const/4 v2, 0x0

    .line 47
    new-array v2, v2, [B

    .line 48
    .line 49
    invoke-virtual {p1, p0, v2}, Lhu/q;->w([B[B)[B

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    invoke-static {}, Lcom/google/crypto/tink/shaded/protobuf/p;->a()Lcom/google/crypto/tink/shaded/protobuf/p;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    invoke-static {p0, p1}, Lqr/y;->t([BLcom/google/crypto/tink/shaded/protobuf/p;)Lqr/y;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    invoke-virtual {p0}, Lqr/y;->p()I

    .line 62
    .line 63
    .line 64
    move-result p1
    :try_end_0
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_0 .. :try_end_0} :catch_0

    .line 65
    if-lez p1, :cond_1

    .line 66
    .line 67
    const/16 p1, 0x15

    .line 68
    .line 69
    invoke-direct {v0, p0, p1}, Lhu/q;-><init>(Ljava/lang/Object;I)V

    .line 70
    .line 71
    .line 72
    return-object v0

    .line 73
    :cond_1
    :try_start_1
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 74
    .line 75
    invoke-direct {p0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw p0
    :try_end_1
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_1 .. :try_end_1} :catch_0

    .line 79
    :catch_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 80
    .line 81
    const-string p1, "invalid keyset, corrupted key material"

    .line 82
    .line 83
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw p0

    .line 87
    :cond_2
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 88
    .line 89
    invoke-direct {p0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    throw p0
.end method

.method public static f()Lh6/e;
    .locals 3

    .line 1
    new-instance v0, Lh6/e;

    .line 2
    .line 3
    new-instance v1, Ljava/util/BitSet;

    .line 4
    .line 5
    invoke-direct {v1}, Ljava/util/BitSet;-><init>()V

    .line 6
    .line 7
    .line 8
    const/4 v2, 0x3

    .line 9
    invoke-direct {v0, v1, v2}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method


# virtual methods
.method public A(I)Lka/v0;
    .locals 6

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 4
    .line 5
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 6
    .line 7
    invoke-virtual {v0}, Lil/g;->M()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x0

    .line 13
    move-object v3, v1

    .line 14
    :goto_0
    if-ge v2, v0, :cond_3

    .line 15
    .line 16
    iget-object v4, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 17
    .line 18
    invoke-virtual {v4, v2}, Lil/g;->L(I)Landroid/view/View;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    invoke-static {v4}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    if-eqz v4, :cond_2

    .line 27
    .line 28
    invoke-virtual {v4}, Lka/v0;->h()Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-nez v5, :cond_2

    .line 33
    .line 34
    iget v5, v4, Lka/v0;->c:I

    .line 35
    .line 36
    if-eq v5, p1, :cond_0

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_0
    iget-object v3, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 40
    .line 41
    iget-object v5, v4, Lka/v0;->a:Landroid/view/View;

    .line 42
    .line 43
    iget-object v3, v3, Lil/g;->g:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v3, Ljava/util/ArrayList;

    .line 46
    .line 47
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    if-eqz v3, :cond_1

    .line 52
    .line 53
    move-object v3, v4

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    move-object v3, v4

    .line 56
    goto :goto_2

    .line 57
    :cond_2
    :goto_1
    add-int/lit8 v2, v2, 0x1

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_3
    :goto_2
    if-nez v3, :cond_4

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_4
    iget-object p0, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 64
    .line 65
    iget-object p1, v3, Lka/v0;->a:Landroid/view/View;

    .line 66
    .line 67
    iget-object p0, p0, Lil/g;->g:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast p0, Ljava/util/ArrayList;

    .line 70
    .line 71
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->contains(Ljava/lang/Object;)Z

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    if-eqz p0, :cond_5

    .line 76
    .line 77
    :goto_3
    return-object v1

    .line 78
    :cond_5
    return-object v3
.end method

.method public B()Ll2/t2;
    .locals 3

    .line 1
    invoke-static {}, Ls6/h;->a()Ls6/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Ls6/h;->c()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x1

    .line 10
    if-ne v1, v2, :cond_0

    .line 11
    .line 12
    new-instance p0, Lo4/j;

    .line 13
    .line 14
    invoke-direct {p0, v2}, Lo4/j;-><init>(Z)V

    .line 15
    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 19
    .line 20
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    new-instance v2, Lo4/f;

    .line 25
    .line 26
    invoke-direct {v2, v1, p0}, Lo4/f;-><init>(Ll2/j1;Lhu/q;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0, v2}, Ls6/h;->h(Ls6/f;)V

    .line 30
    .line 31
    .line 32
    return-object v1
.end method

.method public C()Lor/e;
    .locals 16

    .line 1
    sget-object v0, Lmr/g;->e:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    const-class v1, Lmr/b;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lmr/e;

    .line 10
    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v0, v1

    .line 16
    :goto_0
    const-string v3, "No wrapper found for "

    .line 17
    .line 18
    if-eqz v0, :cond_21

    .line 19
    .line 20
    move-object/from16 v4, p0

    .line 21
    .line 22
    iget-object v4, v4, Lhu/q;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast v4, Lqr/y;

    .line 25
    .line 26
    sget v5, Lmr/h;->a:I

    .line 27
    .line 28
    invoke-virtual {v4}, Lqr/y;->r()I

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    invoke-virtual {v4}, Lqr/y;->q()Ljava/util/List;

    .line 33
    .line 34
    .line 35
    move-result-object v6

    .line 36
    invoke-interface {v6}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object v6

    .line 40
    const/4 v7, 0x0

    .line 41
    const/4 v8, 0x1

    .line 42
    move v9, v7

    .line 43
    move v10, v9

    .line 44
    move v11, v8

    .line 45
    :goto_1
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 46
    .line 47
    .line 48
    move-result v12

    .line 49
    sget-object v13, Lqr/r;->f:Lqr/r;

    .line 50
    .line 51
    if-eqz v12, :cond_8

    .line 52
    .line 53
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v12

    .line 57
    check-cast v12, Lqr/x;

    .line 58
    .line 59
    invoke-virtual {v12}, Lqr/x;->t()Lqr/r;

    .line 60
    .line 61
    .line 62
    move-result-object v14

    .line 63
    if-eq v14, v13, :cond_1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    invoke-virtual {v12}, Lqr/x;->u()Z

    .line 67
    .line 68
    .line 69
    move-result v13

    .line 70
    if-eqz v13, :cond_7

    .line 71
    .line 72
    invoke-virtual {v12}, Lqr/x;->s()Lqr/d0;

    .line 73
    .line 74
    .line 75
    move-result-object v13

    .line 76
    sget-object v14, Lqr/d0;->e:Lqr/d0;

    .line 77
    .line 78
    if-eq v13, v14, :cond_6

    .line 79
    .line 80
    invoke-virtual {v12}, Lqr/x;->t()Lqr/r;

    .line 81
    .line 82
    .line 83
    move-result-object v13

    .line 84
    sget-object v14, Lqr/r;->e:Lqr/r;

    .line 85
    .line 86
    if-eq v13, v14, :cond_5

    .line 87
    .line 88
    invoke-virtual {v12}, Lqr/x;->r()I

    .line 89
    .line 90
    .line 91
    move-result v13

    .line 92
    if-ne v13, v5, :cond_3

    .line 93
    .line 94
    if-nez v10, :cond_2

    .line 95
    .line 96
    move v10, v8

    .line 97
    goto :goto_2

    .line 98
    :cond_2
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 99
    .line 100
    const-string v1, "keyset contains multiple primary keys"

    .line 101
    .line 102
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    throw v0

    .line 106
    :cond_3
    :goto_2
    invoke-virtual {v12}, Lqr/x;->q()Lqr/q;

    .line 107
    .line 108
    .line 109
    move-result-object v12

    .line 110
    invoke-virtual {v12}, Lqr/q;->q()Lqr/p;

    .line 111
    .line 112
    .line 113
    move-result-object v12

    .line 114
    sget-object v13, Lqr/p;->h:Lqr/p;

    .line 115
    .line 116
    if-eq v12, v13, :cond_4

    .line 117
    .line 118
    move v11, v7

    .line 119
    :cond_4
    add-int/lit8 v9, v9, 0x1

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_5
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 123
    .line 124
    invoke-virtual {v12}, Lqr/x;->r()I

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object v1

    .line 136
    const-string v2, "key %d has unknown status"

    .line 137
    .line 138
    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 143
    .line 144
    .line 145
    throw v0

    .line 146
    :cond_6
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 147
    .line 148
    invoke-virtual {v12}, Lqr/x;->r()I

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 153
    .line 154
    .line 155
    move-result-object v1

    .line 156
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    const-string v2, "key %d has unknown prefix"

    .line 161
    .line 162
    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 167
    .line 168
    .line 169
    throw v0

    .line 170
    :cond_7
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 171
    .line 172
    invoke-virtual {v12}, Lqr/x;->r()I

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 177
    .line 178
    .line 179
    move-result-object v1

    .line 180
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    const-string v2, "key %d has no key data"

    .line 185
    .line 186
    invoke-static {v2, v1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 187
    .line 188
    .line 189
    move-result-object v1

    .line 190
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 191
    .line 192
    .line 193
    throw v0

    .line 194
    :cond_8
    if-eqz v9, :cond_20

    .line 195
    .line 196
    if-nez v10, :cond_a

    .line 197
    .line 198
    if-eqz v11, :cond_9

    .line 199
    .line 200
    goto :goto_3

    .line 201
    :cond_9
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 202
    .line 203
    const-string v1, "keyset doesn\'t contain a valid primary key"

    .line 204
    .line 205
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    throw v0

    .line 209
    :cond_a
    :goto_3
    new-instance v5, Lil/g;

    .line 210
    .line 211
    invoke-direct {v5, v0}, Lil/g;-><init>(Ljava/lang/Class;)V

    .line 212
    .line 213
    .line 214
    iget-object v6, v5, Lil/g;->g:Ljava/lang/Object;

    .line 215
    .line 216
    check-cast v6, Ljava/lang/Class;

    .line 217
    .line 218
    invoke-virtual {v4}, Lqr/y;->q()Ljava/util/List;

    .line 219
    .line 220
    .line 221
    move-result-object v9

    .line 222
    invoke-interface {v9}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 223
    .line 224
    .line 225
    move-result-object v9

    .line 226
    :goto_4
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    .line 227
    .line 228
    .line 229
    move-result v10

    .line 230
    if-eqz v10, :cond_1d

    .line 231
    .line 232
    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v10

    .line 236
    check-cast v10, Lqr/x;

    .line 237
    .line 238
    invoke-virtual {v10}, Lqr/x;->t()Lqr/r;

    .line 239
    .line 240
    .line 241
    move-result-object v11

    .line 242
    if-ne v11, v13, :cond_1c

    .line 243
    .line 244
    invoke-virtual {v10}, Lqr/x;->q()Lqr/q;

    .line 245
    .line 246
    .line 247
    move-result-object v11

    .line 248
    invoke-virtual {v11}, Lqr/q;->r()Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object v11

    .line 252
    invoke-virtual {v10}, Lqr/x;->q()Lqr/q;

    .line 253
    .line 254
    .line 255
    move-result-object v12

    .line 256
    invoke-virtual {v12}, Lqr/q;->s()Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 257
    .line 258
    .line 259
    move-result-object v12

    .line 260
    invoke-static {v11}, Lmr/g;->b(Ljava/lang/String;)Lmr/f;

    .line 261
    .line 262
    .line 263
    move-result-object v11

    .line 264
    iget-object v14, v11, Lmr/f;->a:Leb/j0;

    .line 265
    .line 266
    iget-object v11, v11, Lmr/f;->a:Leb/j0;

    .line 267
    .line 268
    iget-object v14, v14, Leb/j0;->f:Ljava/lang/Object;

    .line 269
    .line 270
    check-cast v14, Ljava/util/Map;

    .line 271
    .line 272
    invoke-interface {v14}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 273
    .line 274
    .line 275
    move-result-object v14

    .line 276
    iget-object v15, v11, Leb/j0;->f:Ljava/lang/Object;

    .line 277
    .line 278
    check-cast v15, Ljava/util/Map;

    .line 279
    .line 280
    invoke-interface {v14, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    move-result v14

    .line 284
    if-eqz v14, :cond_19

    .line 285
    .line 286
    :try_start_0
    invoke-interface {v15}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 287
    .line 288
    .line 289
    move-result-object v14

    .line 290
    invoke-interface {v14, v0}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 291
    .line 292
    .line 293
    move-result v14
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_1

    .line 294
    const-class v2, Ljava/lang/Void;

    .line 295
    .line 296
    if-nez v14, :cond_c

    .line 297
    .line 298
    :try_start_1
    invoke-virtual {v2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 299
    .line 300
    .line 301
    move-result v14

    .line 302
    if-eqz v14, :cond_b

    .line 303
    .line 304
    goto :goto_5

    .line 305
    :cond_b
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 306
    .line 307
    invoke-virtual {v11}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 308
    .line 309
    .line 310
    move-result-object v2

    .line 311
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 312
    .line 313
    .line 314
    move-result-object v0

    .line 315
    new-instance v3, Ljava/lang/StringBuilder;

    .line 316
    .line 317
    const-string v4, "Given internalKeyMananger "

    .line 318
    .line 319
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 320
    .line 321
    .line 322
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 323
    .line 324
    .line 325
    const-string v2, " does not support primitive class "

    .line 326
    .line 327
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 328
    .line 329
    .line 330
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 331
    .line 332
    .line 333
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 334
    .line 335
    .line 336
    move-result-object v0

    .line 337
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    throw v1
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    .line 341
    :cond_c
    :goto_5
    :try_start_2
    invoke-virtual {v11, v12}, Leb/j0;->A(Lcom/google/crypto/tink/shaded/protobuf/i;)Lcom/google/crypto/tink/shaded/protobuf/a;

    .line 342
    .line 343
    .line 344
    move-result-object v12

    .line 345
    invoke-virtual {v2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 346
    .line 347
    .line 348
    move-result v2

    .line 349
    if-nez v2, :cond_18

    .line 350
    .line 351
    invoke-virtual {v11, v12}, Leb/j0;->I(Lcom/google/crypto/tink/shaded/protobuf/a;)V

    .line 352
    .line 353
    .line 354
    invoke-interface {v15, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 355
    .line 356
    .line 357
    move-result-object v2

    .line 358
    check-cast v2, Lor/a;

    .line 359
    .line 360
    if-eqz v2, :cond_17

    .line 361
    .line 362
    invoke-virtual {v2, v12}, Lor/a;->a(Lcom/google/crypto/tink/shaded/protobuf/a;)Lrr/d;

    .line 363
    .line 364
    .line 365
    move-result-object v2
    :try_end_2
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_2 .. :try_end_2} :catch_0

    .line 366
    iget-object v11, v5, Lil/g;->e:Ljava/lang/Object;

    .line 367
    .line 368
    check-cast v11, Ljava/util/concurrent/ConcurrentHashMap;

    .line 369
    .line 370
    invoke-virtual {v10}, Lqr/x;->t()Lqr/r;

    .line 371
    .line 372
    .line 373
    move-result-object v12

    .line 374
    if-ne v12, v13, :cond_16

    .line 375
    .line 376
    new-instance v12, Lmr/c;

    .line 377
    .line 378
    invoke-virtual {v10}, Lqr/x;->s()Lqr/d0;

    .line 379
    .line 380
    .line 381
    move-result-object v14

    .line 382
    invoke-virtual {v14}, Ljava/lang/Enum;->ordinal()I

    .line 383
    .line 384
    .line 385
    move-result v14

    .line 386
    if-eq v14, v8, :cond_10

    .line 387
    .line 388
    const/16 p0, 0x5

    .line 389
    .line 390
    const/4 v15, 0x2

    .line 391
    if-eq v14, v15, :cond_f

    .line 392
    .line 393
    const/4 v15, 0x3

    .line 394
    if-eq v14, v15, :cond_e

    .line 395
    .line 396
    const/4 v15, 0x4

    .line 397
    if-ne v14, v15, :cond_d

    .line 398
    .line 399
    goto :goto_6

    .line 400
    :cond_d
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 401
    .line 402
    const-string v1, "unknown output prefix type"

    .line 403
    .line 404
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 405
    .line 406
    .line 407
    throw v0

    .line 408
    :cond_e
    sget-object v14, Lmr/a;->a:[B

    .line 409
    .line 410
    goto :goto_7

    .line 411
    :cond_f
    :goto_6
    invoke-static/range {p0 .. p0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 412
    .line 413
    .line 414
    move-result-object v14

    .line 415
    invoke-virtual {v14, v7}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 416
    .line 417
    .line 418
    move-result-object v14

    .line 419
    invoke-virtual {v10}, Lqr/x;->r()I

    .line 420
    .line 421
    .line 422
    move-result v15

    .line 423
    invoke-virtual {v14, v15}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 424
    .line 425
    .line 426
    move-result-object v14

    .line 427
    invoke-virtual {v14}, Ljava/nio/ByteBuffer;->array()[B

    .line 428
    .line 429
    .line 430
    move-result-object v14

    .line 431
    goto :goto_7

    .line 432
    :cond_10
    const/16 p0, 0x5

    .line 433
    .line 434
    invoke-static/range {p0 .. p0}, Ljava/nio/ByteBuffer;->allocate(I)Ljava/nio/ByteBuffer;

    .line 435
    .line 436
    .line 437
    move-result-object v14

    .line 438
    invoke-virtual {v14, v8}, Ljava/nio/ByteBuffer;->put(B)Ljava/nio/ByteBuffer;

    .line 439
    .line 440
    .line 441
    move-result-object v14

    .line 442
    invoke-virtual {v10}, Lqr/x;->r()I

    .line 443
    .line 444
    .line 445
    move-result v15

    .line 446
    invoke-virtual {v14, v15}, Ljava/nio/ByteBuffer;->putInt(I)Ljava/nio/ByteBuffer;

    .line 447
    .line 448
    .line 449
    move-result-object v14

    .line 450
    invoke-virtual {v14}, Ljava/nio/ByteBuffer;->array()[B

    .line 451
    .line 452
    .line 453
    move-result-object v14

    .line 454
    :goto_7
    invoke-virtual {v10}, Lqr/x;->t()Lqr/r;

    .line 455
    .line 456
    .line 457
    move-result-object v15

    .line 458
    invoke-virtual {v10}, Lqr/x;->s()Lqr/d0;

    .line 459
    .line 460
    .line 461
    move-result-object v7

    .line 462
    invoke-direct {v12, v2, v14, v15, v7}, Lmr/c;-><init>(Ljava/lang/Object;[BLqr/r;Lqr/d0;)V

    .line 463
    .line 464
    .line 465
    new-instance v2, Ljava/util/ArrayList;

    .line 466
    .line 467
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 468
    .line 469
    .line 470
    invoke-virtual {v2, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 471
    .line 472
    .line 473
    new-instance v7, Lmr/d;

    .line 474
    .line 475
    iget-object v14, v12, Lmr/c;->b:[B

    .line 476
    .line 477
    if-nez v14, :cond_11

    .line 478
    .line 479
    const/4 v15, 0x0

    .line 480
    goto :goto_8

    .line 481
    :cond_11
    array-length v15, v14

    .line 482
    invoke-static {v14, v15}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 483
    .line 484
    .line 485
    move-result-object v15

    .line 486
    :goto_8
    invoke-direct {v7, v15}, Lmr/d;-><init>([B)V

    .line 487
    .line 488
    .line 489
    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 490
    .line 491
    .line 492
    move-result-object v2

    .line 493
    invoke-virtual {v11, v7, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 494
    .line 495
    .line 496
    move-result-object v2

    .line 497
    check-cast v2, Ljava/util/List;

    .line 498
    .line 499
    if-eqz v2, :cond_12

    .line 500
    .line 501
    new-instance v15, Ljava/util/ArrayList;

    .line 502
    .line 503
    invoke-direct {v15}, Ljava/util/ArrayList;-><init>()V

    .line 504
    .line 505
    .line 506
    invoke-virtual {v15, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 507
    .line 508
    .line 509
    invoke-virtual {v15, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 510
    .line 511
    .line 512
    invoke-static {v15}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 513
    .line 514
    .line 515
    move-result-object v2

    .line 516
    invoke-virtual {v11, v7, v2}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 517
    .line 518
    .line 519
    :cond_12
    invoke-virtual {v10}, Lqr/x;->r()I

    .line 520
    .line 521
    .line 522
    move-result v2

    .line 523
    invoke-virtual {v4}, Lqr/y;->r()I

    .line 524
    .line 525
    .line 526
    move-result v7

    .line 527
    if-ne v2, v7, :cond_1c

    .line 528
    .line 529
    iget-object v2, v12, Lmr/c;->c:Lqr/r;

    .line 530
    .line 531
    if-ne v2, v13, :cond_15

    .line 532
    .line 533
    if-nez v14, :cond_13

    .line 534
    .line 535
    const/4 v2, 0x0

    .line 536
    goto :goto_9

    .line 537
    :cond_13
    array-length v2, v14

    .line 538
    invoke-static {v14, v2}, Ljava/util/Arrays;->copyOf([BI)[B

    .line 539
    .line 540
    .line 541
    move-result-object v2

    .line 542
    :goto_9
    invoke-virtual {v5, v2}, Lil/g;->H([B)Ljava/util/List;

    .line 543
    .line 544
    .line 545
    move-result-object v2

    .line 546
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 547
    .line 548
    .line 549
    move-result v2

    .line 550
    if-nez v2, :cond_14

    .line 551
    .line 552
    iput-object v12, v5, Lil/g;->f:Ljava/lang/Object;

    .line 553
    .line 554
    goto/16 :goto_b

    .line 555
    .line 556
    :cond_14
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 557
    .line 558
    const-string v1, "the primary entry cannot be set to an entry which is not held by this primitive set"

    .line 559
    .line 560
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 561
    .line 562
    .line 563
    throw v0

    .line 564
    :cond_15
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 565
    .line 566
    const-string v1, "the primary entry has to be ENABLED"

    .line 567
    .line 568
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 569
    .line 570
    .line 571
    throw v0

    .line 572
    :cond_16
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 573
    .line 574
    const-string v1, "only ENABLED key is allowed"

    .line 575
    .line 576
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 577
    .line 578
    .line 579
    throw v0

    .line 580
    :cond_17
    :try_start_3
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 581
    .line 582
    new-instance v2, Ljava/lang/StringBuilder;

    .line 583
    .line 584
    const-string v3, "Requested primitive class "

    .line 585
    .line 586
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 587
    .line 588
    .line 589
    invoke-virtual {v0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 590
    .line 591
    .line 592
    move-result-object v0

    .line 593
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 594
    .line 595
    .line 596
    const-string v0, " not supported."

    .line 597
    .line 598
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 599
    .line 600
    .line 601
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 602
    .line 603
    .line 604
    move-result-object v0

    .line 605
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 606
    .line 607
    .line 608
    throw v1

    .line 609
    :cond_18
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 610
    .line 611
    const-string v1, "Cannot create a primitive for Void"

    .line 612
    .line 613
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 614
    .line 615
    .line 616
    throw v0
    :try_end_3
    .catch Lcom/google/crypto/tink/shaded/protobuf/d0; {:try_start_3 .. :try_end_3} :catch_0

    .line 617
    :catch_0
    move-exception v0

    .line 618
    new-instance v1, Ljava/security/GeneralSecurityException;

    .line 619
    .line 620
    iget-object v2, v11, Leb/j0;->e:Ljava/lang/Object;

    .line 621
    .line 622
    check-cast v2, Ljava/lang/Class;

    .line 623
    .line 624
    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 625
    .line 626
    .line 627
    move-result-object v2

    .line 628
    const-string v3, "Failures parsing proto of type "

    .line 629
    .line 630
    invoke-virtual {v3, v2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 631
    .line 632
    .line 633
    move-result-object v2

    .line 634
    invoke-direct {v1, v2, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 635
    .line 636
    .line 637
    throw v1

    .line 638
    :catch_1
    move-exception v0

    .line 639
    new-instance v1, Ljava/security/GeneralSecurityException;

    .line 640
    .line 641
    const-string v2, "Primitive type not supported"

    .line 642
    .line 643
    invoke-direct {v1, v2, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 644
    .line 645
    .line 646
    throw v1

    .line 647
    :cond_19
    new-instance v1, Ljava/security/GeneralSecurityException;

    .line 648
    .line 649
    new-instance v2, Ljava/lang/StringBuilder;

    .line 650
    .line 651
    const-string v3, "Primitive type "

    .line 652
    .line 653
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 654
    .line 655
    .line 656
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 657
    .line 658
    .line 659
    move-result-object v0

    .line 660
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 661
    .line 662
    .line 663
    const-string v0, " not supported by key manager of type "

    .line 664
    .line 665
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 666
    .line 667
    .line 668
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 669
    .line 670
    .line 671
    move-result-object v0

    .line 672
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 673
    .line 674
    .line 675
    const-string v0, ", supported primitives: "

    .line 676
    .line 677
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 678
    .line 679
    .line 680
    iget-object v0, v11, Leb/j0;->f:Ljava/lang/Object;

    .line 681
    .line 682
    check-cast v0, Ljava/util/Map;

    .line 683
    .line 684
    invoke-interface {v0}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 685
    .line 686
    .line 687
    move-result-object v0

    .line 688
    new-instance v3, Ljava/lang/StringBuilder;

    .line 689
    .line 690
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 691
    .line 692
    .line 693
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 694
    .line 695
    .line 696
    move-result-object v0

    .line 697
    :goto_a
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 698
    .line 699
    .line 700
    move-result v4

    .line 701
    if-eqz v4, :cond_1b

    .line 702
    .line 703
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 704
    .line 705
    .line 706
    move-result-object v4

    .line 707
    check-cast v4, Ljava/lang/Class;

    .line 708
    .line 709
    if-nez v8, :cond_1a

    .line 710
    .line 711
    const-string v5, ", "

    .line 712
    .line 713
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 714
    .line 715
    .line 716
    :cond_1a
    invoke-virtual {v4}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 717
    .line 718
    .line 719
    move-result-object v4

    .line 720
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 721
    .line 722
    .line 723
    const/4 v8, 0x0

    .line 724
    goto :goto_a

    .line 725
    :cond_1b
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 726
    .line 727
    .line 728
    move-result-object v0

    .line 729
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 730
    .line 731
    .line 732
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 733
    .line 734
    .line 735
    move-result-object v0

    .line 736
    invoke-direct {v1, v0}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 737
    .line 738
    .line 739
    throw v1

    .line 740
    :cond_1c
    :goto_b
    const/4 v7, 0x0

    .line 741
    goto/16 :goto_4

    .line 742
    .line 743
    :cond_1d
    sget-object v0, Lmr/g;->e:Ljava/util/concurrent/ConcurrentHashMap;

    .line 744
    .line 745
    invoke-virtual {v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 746
    .line 747
    .line 748
    move-result-object v0

    .line 749
    check-cast v0, Lmr/e;

    .line 750
    .line 751
    if-eqz v0, :cond_1f

    .line 752
    .line 753
    invoke-virtual {v1, v6}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 754
    .line 755
    .line 756
    move-result v0

    .line 757
    if-eqz v0, :cond_1e

    .line 758
    .line 759
    new-instance v0, Lor/e;

    .line 760
    .line 761
    invoke-direct {v0, v5}, Lor/e;-><init>(Lil/g;)V

    .line 762
    .line 763
    .line 764
    return-object v0

    .line 765
    :cond_1e
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 766
    .line 767
    new-instance v2, Ljava/lang/StringBuilder;

    .line 768
    .line 769
    const-string v3, "Wrong input primitive class, expected "

    .line 770
    .line 771
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 772
    .line 773
    .line 774
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 775
    .line 776
    .line 777
    const-string v1, ", got "

    .line 778
    .line 779
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 780
    .line 781
    .line 782
    invoke-virtual {v2, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 783
    .line 784
    .line 785
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 786
    .line 787
    .line 788
    move-result-object v1

    .line 789
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 790
    .line 791
    .line 792
    throw v0

    .line 793
    :cond_1f
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 794
    .line 795
    invoke-virtual {v6}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 796
    .line 797
    .line 798
    move-result-object v1

    .line 799
    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 800
    .line 801
    .line 802
    move-result-object v1

    .line 803
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 804
    .line 805
    .line 806
    throw v0

    .line 807
    :cond_20
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 808
    .line 809
    const-string v1, "keyset must contain at least one ENABLED key"

    .line 810
    .line 811
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 812
    .line 813
    .line 814
    throw v0

    .line 815
    :cond_21
    new-instance v0, Ljava/security/GeneralSecurityException;

    .line 816
    .line 817
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 818
    .line 819
    .line 820
    move-result-object v1

    .line 821
    invoke-virtual {v3, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 822
    .line 823
    .line 824
    move-result-object v1

    .line 825
    invoke-direct {v0, v1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 826
    .line 827
    .line 828
    throw v0
.end method

.method public D(F)V
    .locals 1

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v0, Lj3/t;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Lj3/t;-><init>(F)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public E(Ljava/util/Set;)V
    .locals 6

    .line 1
    const-string v0, "tableIds"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1}, Ljava/util/Set;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    goto :goto_2

    .line 13
    :cond_0
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p0, Lyy0/c2;

    .line 16
    .line 17
    :cond_1
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    move-object v1, v0

    .line 22
    check-cast v1, [I

    .line 23
    .line 24
    array-length v2, v1

    .line 25
    new-array v3, v2, [I

    .line 26
    .line 27
    const/4 v4, 0x0

    .line 28
    :goto_0
    if-ge v4, v2, :cond_3

    .line 29
    .line 30
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 31
    .line 32
    .line 33
    move-result-object v5

    .line 34
    invoke-interface {p1, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    if-eqz v5, :cond_2

    .line 39
    .line 40
    aget v5, v1, v4

    .line 41
    .line 42
    add-int/lit8 v5, v5, 0x1

    .line 43
    .line 44
    goto :goto_1

    .line 45
    :cond_2
    aget v5, v1, v4

    .line 46
    .line 47
    :goto_1
    aput v5, v3, v4

    .line 48
    .line 49
    add-int/lit8 v4, v4, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_3
    invoke-virtual {p0, v0, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    if-eqz v0, :cond_1

    .line 57
    .line 58
    :goto_2
    return-void
.end method

.method public F(FF)V
    .locals 1

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v0, Lj3/m;

    .line 6
    .line 7
    invoke-direct {v0, p1, p2}, Lj3/m;-><init>(FF)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public G(FF)V
    .locals 1

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v0, Lj3/u;

    .line 6
    .line 7
    invoke-direct {v0, p1, p2}, Lj3/u;-><init>(FF)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public H(II)V
    .locals 7

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 4
    .line 5
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 6
    .line 7
    invoke-virtual {v0}, Lil/g;->M()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    add-int/2addr p2, p1

    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    const/4 v2, 0x2

    .line 14
    const/4 v3, 0x1

    .line 15
    if-ge v1, v0, :cond_2

    .line 16
    .line 17
    iget-object v4, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 18
    .line 19
    invoke-virtual {v4, v1}, Lil/g;->L(I)Landroid/view/View;

    .line 20
    .line 21
    .line 22
    move-result-object v4

    .line 23
    invoke-static {v4}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 24
    .line 25
    .line 26
    move-result-object v5

    .line 27
    if-eqz v5, :cond_1

    .line 28
    .line 29
    invoke-virtual {v5}, Lka/v0;->o()Z

    .line 30
    .line 31
    .line 32
    move-result v6

    .line 33
    if-eqz v6, :cond_0

    .line 34
    .line 35
    goto :goto_1

    .line 36
    :cond_0
    iget v6, v5, Lka/v0;->c:I

    .line 37
    .line 38
    if-lt v6, p1, :cond_1

    .line 39
    .line 40
    if-ge v6, p2, :cond_1

    .line 41
    .line 42
    invoke-virtual {v5, v2}, Lka/v0;->a(I)V

    .line 43
    .line 44
    .line 45
    const/16 v2, 0x400

    .line 46
    .line 47
    invoke-virtual {v5, v2}, Lka/v0;->a(I)V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v4}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    check-cast v2, Lka/g0;

    .line 55
    .line 56
    iput-boolean v3, v2, Lka/g0;->c:Z

    .line 57
    .line 58
    :cond_1
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->f:Lka/l0;

    .line 62
    .line 63
    iget-object v1, v0, Lka/l0;->c:Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 66
    .line 67
    .line 68
    move-result v4

    .line 69
    sub-int/2addr v4, v3

    .line 70
    :goto_2
    if-ltz v4, :cond_5

    .line 71
    .line 72
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object v5

    .line 76
    check-cast v5, Lka/v0;

    .line 77
    .line 78
    if-nez v5, :cond_3

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_3
    iget v6, v5, Lka/v0;->c:I

    .line 82
    .line 83
    if-lt v6, p1, :cond_4

    .line 84
    .line 85
    if-ge v6, p2, :cond_4

    .line 86
    .line 87
    invoke-virtual {v5, v2}, Lka/v0;->a(I)V

    .line 88
    .line 89
    .line 90
    invoke-virtual {v0, v4}, Lka/l0;->h(I)V

    .line 91
    .line 92
    .line 93
    :cond_4
    :goto_3
    add-int/lit8 v4, v4, -0x1

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_5
    iput-boolean v3, p0, Landroidx/recyclerview/widget/RecyclerView;->u1:Z

    .line 97
    .line 98
    return-void
.end method

.method public I(FF)V
    .locals 1

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v0, Lj3/n;

    .line 6
    .line 7
    invoke-direct {v0, p1, p2}, Lj3/n;-><init>(FF)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public J()Lh6/e;
    .locals 2

    .line 1
    new-instance v0, Lh6/e;

    .line 2
    .line 3
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Ljava/util/BitSet;

    .line 6
    .line 7
    invoke-virtual {p0}, Ljava/util/BitSet;->clone()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/util/BitSet;

    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    invoke-direct {v0, p0, v1}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public K(II)V
    .locals 7

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 4
    .line 5
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 6
    .line 7
    invoke-virtual {v0}, Lil/g;->M()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x0

    .line 12
    move v2, v1

    .line 13
    :goto_0
    const/4 v3, 0x1

    .line 14
    if-ge v2, v0, :cond_1

    .line 15
    .line 16
    iget-object v4, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 17
    .line 18
    invoke-virtual {v4, v2}, Lil/g;->L(I)Landroid/view/View;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    invoke-static {v4}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 23
    .line 24
    .line 25
    move-result-object v4

    .line 26
    if-eqz v4, :cond_0

    .line 27
    .line 28
    invoke-virtual {v4}, Lka/v0;->o()Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    if-nez v5, :cond_0

    .line 33
    .line 34
    iget v5, v4, Lka/v0;->c:I

    .line 35
    .line 36
    if-lt v5, p1, :cond_0

    .line 37
    .line 38
    invoke-virtual {v4, p2, v1}, Lka/v0;->l(IZ)V

    .line 39
    .line 40
    .line 41
    iget-object v4, p0, Landroidx/recyclerview/widget/RecyclerView;->q1:Lka/r0;

    .line 42
    .line 43
    iput-boolean v3, v4, Lka/r0;->f:Z

    .line 44
    .line 45
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_1
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->f:Lka/l0;

    .line 49
    .line 50
    iget-object v0, v0, Lka/l0;->c:Ljava/util/ArrayList;

    .line 51
    .line 52
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    move v4, v1

    .line 57
    :goto_1
    if-ge v4, v2, :cond_3

    .line 58
    .line 59
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object v5

    .line 63
    check-cast v5, Lka/v0;

    .line 64
    .line 65
    if-eqz v5, :cond_2

    .line 66
    .line 67
    iget v6, v5, Lka/v0;->c:I

    .line 68
    .line 69
    if-lt v6, p1, :cond_2

    .line 70
    .line 71
    invoke-virtual {v5, p2, v1}, Lka/v0;->l(IZ)V

    .line 72
    .line 73
    .line 74
    :cond_2
    add-int/lit8 v4, v4, 0x1

    .line 75
    .line 76
    goto :goto_1

    .line 77
    :cond_3
    invoke-virtual {p0}, Landroidx/recyclerview/widget/RecyclerView;->requestLayout()V

    .line 78
    .line 79
    .line 80
    iput-boolean v3, p0, Landroidx/recyclerview/widget/RecyclerView;->t1:Z

    .line 81
    .line 82
    return-void
.end method

.method public L(II)V
    .locals 10

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 4
    .line 5
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 6
    .line 7
    invoke-virtual {v0}, Lil/g;->M()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, -0x1

    .line 12
    const/4 v2, 0x1

    .line 13
    if-ge p1, p2, :cond_0

    .line 14
    .line 15
    move v3, p1

    .line 16
    move v4, p2

    .line 17
    move v5, v1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v4, p1

    .line 20
    move v3, p2

    .line 21
    move v5, v2

    .line 22
    :goto_0
    const/4 v6, 0x0

    .line 23
    move v7, v6

    .line 24
    :goto_1
    if-ge v7, v0, :cond_4

    .line 25
    .line 26
    iget-object v8, p0, Landroidx/recyclerview/widget/RecyclerView;->i:Lil/g;

    .line 27
    .line 28
    invoke-virtual {v8, v7}, Lil/g;->L(I)Landroid/view/View;

    .line 29
    .line 30
    .line 31
    move-result-object v8

    .line 32
    invoke-static {v8}, Landroidx/recyclerview/widget/RecyclerView;->J(Landroid/view/View;)Lka/v0;

    .line 33
    .line 34
    .line 35
    move-result-object v8

    .line 36
    if-eqz v8, :cond_3

    .line 37
    .line 38
    iget v9, v8, Lka/v0;->c:I

    .line 39
    .line 40
    if-lt v9, v3, :cond_3

    .line 41
    .line 42
    if-le v9, v4, :cond_1

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_1
    if-ne v9, p1, :cond_2

    .line 46
    .line 47
    sub-int v9, p2, p1

    .line 48
    .line 49
    invoke-virtual {v8, v9, v6}, Lka/v0;->l(IZ)V

    .line 50
    .line 51
    .line 52
    goto :goto_2

    .line 53
    :cond_2
    invoke-virtual {v8, v5, v6}, Lka/v0;->l(IZ)V

    .line 54
    .line 55
    .line 56
    :goto_2
    iget-object v8, p0, Landroidx/recyclerview/widget/RecyclerView;->q1:Lka/r0;

    .line 57
    .line 58
    iput-boolean v2, v8, Lka/r0;->f:Z

    .line 59
    .line 60
    :cond_3
    :goto_3
    add-int/lit8 v7, v7, 0x1

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_4
    iget-object v0, p0, Landroidx/recyclerview/widget/RecyclerView;->f:Lka/l0;

    .line 64
    .line 65
    iget-object v0, v0, Lka/l0;->c:Ljava/util/ArrayList;

    .line 66
    .line 67
    if-ge p1, p2, :cond_5

    .line 68
    .line 69
    move v3, p1

    .line 70
    move v4, p2

    .line 71
    goto :goto_4

    .line 72
    :cond_5
    move v4, p1

    .line 73
    move v3, p2

    .line 74
    move v1, v2

    .line 75
    :goto_4
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 76
    .line 77
    .line 78
    move-result v5

    .line 79
    move v7, v6

    .line 80
    :goto_5
    if-ge v7, v5, :cond_9

    .line 81
    .line 82
    invoke-virtual {v0, v7}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v8

    .line 86
    check-cast v8, Lka/v0;

    .line 87
    .line 88
    if-eqz v8, :cond_8

    .line 89
    .line 90
    iget v9, v8, Lka/v0;->c:I

    .line 91
    .line 92
    if-lt v9, v3, :cond_8

    .line 93
    .line 94
    if-le v9, v4, :cond_6

    .line 95
    .line 96
    goto :goto_6

    .line 97
    :cond_6
    if-ne v9, p1, :cond_7

    .line 98
    .line 99
    sub-int v9, p2, p1

    .line 100
    .line 101
    invoke-virtual {v8, v9, v6}, Lka/v0;->l(IZ)V

    .line 102
    .line 103
    .line 104
    goto :goto_6

    .line 105
    :cond_7
    invoke-virtual {v8, v1, v6}, Lka/v0;->l(IZ)V

    .line 106
    .line 107
    .line 108
    :cond_8
    :goto_6
    add-int/lit8 v7, v7, 0x1

    .line 109
    .line 110
    goto :goto_5

    .line 111
    :cond_9
    invoke-virtual {p0}, Landroidx/recyclerview/widget/RecyclerView;->requestLayout()V

    .line 112
    .line 113
    .line 114
    iput-boolean v2, p0, Landroidx/recyclerview/widget/RecyclerView;->t1:Z

    .line 115
    .line 116
    return-void
.end method

.method public M(Lc2/k;Lw3/t;)Lcom/google/android/gms/internal/measurement/i4;
    .locals 38

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    move-object/from16 v1, p0

    .line 4
    .line 5
    iget-object v1, v1, Lhu/q;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v1, Landroidx/collection/u;

    .line 8
    .line 9
    new-instance v2, Landroidx/collection/u;

    .line 10
    .line 11
    iget-object v3, v0, Lc2/k;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v3, Ljava/util/List;

    .line 14
    .line 15
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    invoke-direct {v2, v4}, Landroidx/collection/u;-><init>(I)V

    .line 20
    .line 21
    .line 22
    move-object v4, v3

    .line 23
    check-cast v4, Ljava/util/Collection;

    .line 24
    .line 25
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 26
    .line 27
    .line 28
    move-result v4

    .line 29
    const/4 v6, 0x0

    .line 30
    :goto_0
    if-ge v6, v4, :cond_2

    .line 31
    .line 32
    invoke-interface {v3, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v7

    .line 36
    check-cast v7, Lp3/v;

    .line 37
    .line 38
    iget-wide v8, v7, Lp3/v;->a:J

    .line 39
    .line 40
    invoke-virtual {v1, v8, v9}, Landroidx/collection/u;->b(J)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v10

    .line 44
    check-cast v10, Lp3/u;

    .line 45
    .line 46
    if-nez v10, :cond_0

    .line 47
    .line 48
    iget-wide v10, v7, Lp3/v;->b:J

    .line 49
    .line 50
    iget-wide v12, v7, Lp3/v;->d:J

    .line 51
    .line 52
    move-wide/from16 v25, v10

    .line 53
    .line 54
    move-wide/from16 v27, v12

    .line 55
    .line 56
    const/16 v29, 0x0

    .line 57
    .line 58
    move-object/from16 v10, p2

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_0
    iget-wide v11, v10, Lp3/u;->a:J

    .line 62
    .line 63
    iget-boolean v13, v10, Lp3/u;->c:Z

    .line 64
    .line 65
    iget-wide v14, v10, Lp3/u;->b:J

    .line 66
    .line 67
    move-object/from16 v10, p2

    .line 68
    .line 69
    invoke-virtual {v10, v14, v15}, Lw3/t;->D(J)J

    .line 70
    .line 71
    .line 72
    move-result-wide v14

    .line 73
    move-wide/from16 v25, v11

    .line 74
    .line 75
    move/from16 v29, v13

    .line 76
    .line 77
    move-wide/from16 v27, v14

    .line 78
    .line 79
    :goto_1
    iget-wide v11, v7, Lp3/v;->a:J

    .line 80
    .line 81
    new-instance v16, Lp3/t;

    .line 82
    .line 83
    iget-wide v13, v7, Lp3/v;->b:J

    .line 84
    .line 85
    move v15, v6

    .line 86
    iget-wide v5, v7, Lp3/v;->d:J

    .line 87
    .line 88
    move-object/from16 v36, v3

    .line 89
    .line 90
    iget-boolean v3, v7, Lp3/v;->e:Z

    .line 91
    .line 92
    move/from16 v23, v3

    .line 93
    .line 94
    iget v3, v7, Lp3/v;->f:F

    .line 95
    .line 96
    move/from16 v24, v3

    .line 97
    .line 98
    iget v3, v7, Lp3/v;->g:I

    .line 99
    .line 100
    move/from16 v30, v3

    .line 101
    .line 102
    iget-object v3, v7, Lp3/v;->i:Ljava/util/ArrayList;

    .line 103
    .line 104
    move-object/from16 v31, v3

    .line 105
    .line 106
    move/from16 v37, v4

    .line 107
    .line 108
    iget-wide v3, v7, Lp3/v;->j:J

    .line 109
    .line 110
    move-wide/from16 v32, v3

    .line 111
    .line 112
    iget-wide v3, v7, Lp3/v;->k:J

    .line 113
    .line 114
    move-wide/from16 v34, v3

    .line 115
    .line 116
    move-wide/from16 v21, v5

    .line 117
    .line 118
    move-wide/from16 v17, v11

    .line 119
    .line 120
    move-wide/from16 v19, v13

    .line 121
    .line 122
    invoke-direct/range {v16 .. v35}, Lp3/t;-><init>(JJJZFJJZILjava/util/ArrayList;JJ)V

    .line 123
    .line 124
    .line 125
    move-object/from16 v5, v16

    .line 126
    .line 127
    move-wide/from16 v3, v17

    .line 128
    .line 129
    invoke-virtual {v2, v3, v4, v5}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    iget-boolean v3, v7, Lp3/v;->e:Z

    .line 133
    .line 134
    if-eqz v3, :cond_1

    .line 135
    .line 136
    new-instance v16, Lp3/u;

    .line 137
    .line 138
    iget-wide v4, v7, Lp3/v;->b:J

    .line 139
    .line 140
    iget-wide v6, v7, Lp3/v;->c:J

    .line 141
    .line 142
    move/from16 v21, v3

    .line 143
    .line 144
    move-wide/from16 v17, v4

    .line 145
    .line 146
    move-wide/from16 v19, v6

    .line 147
    .line 148
    invoke-direct/range {v16 .. v21}, Lp3/u;-><init>(JJZ)V

    .line 149
    .line 150
    .line 151
    move-object/from16 v3, v16

    .line 152
    .line 153
    invoke-virtual {v1, v8, v9, v3}, Landroidx/collection/u;->e(JLjava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_1
    invoke-virtual {v1, v8, v9}, Landroidx/collection/u;->f(J)V

    .line 158
    .line 159
    .line 160
    :goto_2
    add-int/lit8 v6, v15, 0x1

    .line 161
    .line 162
    move-object/from16 v3, v36

    .line 163
    .line 164
    move/from16 v4, v37

    .line 165
    .line 166
    goto/16 :goto_0

    .line 167
    .line 168
    :cond_2
    new-instance v1, Lcom/google/android/gms/internal/measurement/i4;

    .line 169
    .line 170
    invoke-direct {v1, v2, v0}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Landroidx/collection/u;Lc2/k;)V

    .line 171
    .line 172
    .line 173
    return-object v1
.end method

.method public O(F)V
    .locals 1

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v0, Lj3/z;

    .line 6
    .line 7
    invoke-direct {v0, p1}, Lj3/z;-><init>(F)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public a(Low0/e;)Z
    .locals 1

    .line 1
    const-string v0, "contentType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Low0/e;

    .line 9
    .line 10
    invoke-virtual {p1, p0}, Low0/e;->q(Low0/e;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public b(Landroid/view/View;)I
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lka/g0;

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lka/g0;

    .line 16
    .line 17
    iget-object p1, p1, Lka/g0;->b:Landroid/graphics/Rect;

    .line 18
    .line 19
    iget p1, p1, Landroid/graphics/Rect;->top:I

    .line 20
    .line 21
    sub-int/2addr v0, p1

    .line 22
    iget p0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    .line 23
    .line 24
    sub-int/2addr v0, p0

    .line 25
    return v0
.end method

.method public c()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lka/f0;

    .line 4
    .line 5
    invoke-virtual {p0}, Lka/f0;->G()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    check-cast p2, Ljava/lang/String;

    .line 2
    .line 3
    const-string v0, "newValue"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Ljz0/m;

    .line 11
    .line 12
    iget-object v0, p0, Ljz0/m;->a:Ljz0/u;

    .line 13
    .line 14
    iget-object v1, v0, Ljz0/u;->a:Ljz0/r;

    .line 15
    .line 16
    iget-object p0, p0, Ljz0/m;->b:Ljava/util/List;

    .line 17
    .line 18
    invoke-interface {p0, p2}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    .line 19
    .line 20
    .line 21
    move-result p2

    .line 22
    iget v2, v0, Ljz0/u;->b:I

    .line 23
    .line 24
    add-int/2addr p2, v2

    .line 25
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    invoke-virtual {v1, p1, p2}, Ljz0/r;->d(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    check-cast p1, Ljava/lang/Integer;

    .line 34
    .line 35
    if-eqz p1, :cond_0

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 38
    .line 39
    .line 40
    move-result p1

    .line 41
    iget p2, v0, Ljz0/u;->b:I

    .line 42
    .line 43
    sub-int/2addr p1, p2

    .line 44
    invoke-interface {p0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Ljava/lang/String;

    .line 49
    .line 50
    return-object p0

    .line 51
    :cond_0
    const/4 p0, 0x0

    .line 52
    return-object p0
.end method

.method public e()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/ve;

    .line 4
    .line 5
    iget-object p0, p0, Ljp/ve;->f:Ljava/lang/String;

    .line 6
    .line 7
    return-object p0
.end method

.method public g(Ljava/lang/Object;)Laq/t;
    .locals 2

    .line 1
    check-cast p1, Lus/a;

    .line 2
    .line 3
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Lms/j;

    .line 6
    .line 7
    iget-object p0, p0, Lms/j;->e:Lms/l;

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    const-string p0, "Received null app settings, cannot send reports at crash time."

    .line 13
    .line 14
    const-string p1, "FirebaseCrashlytics"

    .line 15
    .line 16
    invoke-static {p1, p0, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 17
    .line 18
    .line 19
    invoke-static {v0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :cond_0
    invoke-static {p0}, Lms/l;->a(Lms/l;)Laq/t;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    iget-object v1, p0, Lms/l;->m:Lss/b;

    .line 29
    .line 30
    iget-object p0, p0, Lms/l;->e:Lns/d;

    .line 31
    .line 32
    iget-object p0, p0, Lns/d;->a:Lns/b;

    .line 33
    .line 34
    invoke-virtual {v1, p0, v0}, Lss/b;->n(Ljava/util/concurrent/Executor;Ljava/lang/String;)Laq/t;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    const/4 v0, 0x2

    .line 39
    new-array v0, v0, [Laq/j;

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    aput-object p1, v0, v1

    .line 43
    .line 44
    const/4 p1, 0x1

    .line 45
    aput-object p0, v0, p1

    .line 46
    .line 47
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Ljava/util/List;

    .line 52
    .line 53
    invoke-static {p0}, Ljp/l1;->f(Ljava/util/List;)Laq/t;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0
.end method

.method public get()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lj1/a;

    .line 4
    .line 5
    iget-object p0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lsr/f;

    .line 8
    .line 9
    const-string v0, "firebaseApp"

    .line 10
    .line 11
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    sget-object v0, Lhu/l0;->a:Lhu/l0;

    .line 15
    .line 16
    invoke-static {p0}, Lhu/l0;->a(Lsr/f;)Lhu/b;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public getFormat()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/ve;

    .line 4
    .line 5
    iget p0, p0, Ljp/ve;->d:I

    .line 6
    .line 7
    return p0
.end method

.method public h()Landroid/graphics/Rect;
    .locals 7

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/ve;

    .line 4
    .line 5
    iget-object v0, p0, Ljp/ve;->h:[Landroid/graphics/Point;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    const/high16 v1, -0x80000000

    .line 11
    .line 12
    const v2, 0x7fffffff

    .line 13
    .line 14
    .line 15
    move v3, v2

    .line 16
    move v4, v3

    .line 17
    move v2, v1

    .line 18
    :goto_0
    iget-object v5, p0, Ljp/ve;->h:[Landroid/graphics/Point;

    .line 19
    .line 20
    array-length v6, v5

    .line 21
    if-ge v0, v6, :cond_0

    .line 22
    .line 23
    aget-object v5, v5, v0

    .line 24
    .line 25
    iget v6, v5, Landroid/graphics/Point;->x:I

    .line 26
    .line 27
    invoke-static {v3, v6}, Ljava/lang/Math;->min(II)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    iget v6, v5, Landroid/graphics/Point;->x:I

    .line 32
    .line 33
    invoke-static {v1, v6}, Ljava/lang/Math;->max(II)I

    .line 34
    .line 35
    .line 36
    move-result v1

    .line 37
    iget v6, v5, Landroid/graphics/Point;->y:I

    .line 38
    .line 39
    invoke-static {v4, v6}, Ljava/lang/Math;->min(II)I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    iget v5, v5, Landroid/graphics/Point;->y:I

    .line 44
    .line 45
    invoke-static {v2, v5}, Ljava/lang/Math;->max(II)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    add-int/lit8 v0, v0, 0x1

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    new-instance p0, Landroid/graphics/Rect;

    .line 53
    .line 54
    invoke-direct {p0, v3, v4, v1, v2}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 55
    .line 56
    .line 57
    return-object p0

    .line 58
    :cond_1
    const/4 p0, 0x0

    .line 59
    return-object p0
.end method

.method public i()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/ve;

    .line 4
    .line 5
    iget-object p0, p0, Ljp/ve;->e:Ljava/lang/String;

    .line 6
    .line 7
    return-object p0
.end method

.method public j(Landroid/os/Bundle;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lwr/b;

    .line 4
    .line 5
    const-string v0, "clx"

    .line 6
    .line 7
    check-cast p0, Lwr/c;

    .line 8
    .line 9
    const-string v1, "_ae"

    .line 10
    .line 11
    invoke-virtual {p0, v0, v1, p1}, Lwr/c;->a(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public k()I
    .locals 0

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/ve;

    .line 4
    .line 5
    iget p0, p0, Ljp/ve;->g:I

    .line 6
    .line 7
    return p0
.end method

.method public l()V
    .locals 1

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    sget-object v0, Lj3/j;->c:Lj3/j;

    .line 6
    .line 7
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public m(Ll/l;Landroid/view/MenuItem;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ll/f;

    .line 4
    .line 5
    iget-object p0, p0, Ll/f;->i:Landroid/os/Handler;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public n()I
    .locals 1

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lka/f0;

    .line 4
    .line 5
    iget v0, p0, Lka/f0;->o:I

    .line 6
    .line 7
    invoke-virtual {p0}, Lka/f0;->D()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    sub-int/2addr v0, p0

    .line 12
    return v0
.end method

.method public o(Le1/b0;Lrx0/c;)V
    .locals 4

    .line 1
    instance-of v0, p2, Lla/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lla/m;

    .line 7
    .line 8
    iget v1, v0, Lla/m;->f:I

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
    iput v1, v0, Lla/m;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lla/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lla/m;-><init>(Lhu/q;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lla/m;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, Lla/m;->f:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-eq v1, v2, :cond_1

    .line 35
    .line 36
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p2}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast p0, Lyy0/c2;

    .line 55
    .line 56
    iput v2, v0, Lla/m;->f:I

    .line 57
    .line 58
    invoke-virtual {p0, p1, v0}, Lyy0/c2;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    return-void
.end method

.method public p()[Landroid/graphics/Point;
    .locals 0

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljp/ve;

    .line 4
    .line 5
    iget-object p0, p0, Ljp/ve;->h:[Landroid/graphics/Point;

    .line 6
    .line 7
    return-object p0
.end method

.method public q(Ll/l;Ll/n;)V
    .locals 10

    .line 1
    iget-object v0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ll/f;

    .line 4
    .line 5
    iget-object v1, v0, Ll/f;->i:Landroid/os/Handler;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-virtual {v1, v2}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, v0, Ll/f;->k:Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    const/4 v4, 0x0

    .line 18
    :goto_0
    const/4 v5, -0x1

    .line 19
    if-ge v4, v3, :cond_1

    .line 20
    .line 21
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v6

    .line 25
    check-cast v6, Ll/e;

    .line 26
    .line 27
    iget-object v6, v6, Ll/e;->b:Ll/l;

    .line 28
    .line 29
    if-ne p1, v6, :cond_0

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_0
    add-int/lit8 v4, v4, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    move v4, v5

    .line 36
    :goto_1
    if-ne v4, v5, :cond_2

    .line 37
    .line 38
    return-void

    .line 39
    :cond_2
    add-int/lit8 v4, v4, 0x1

    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-ge v4, v3, :cond_3

    .line 46
    .line 47
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    move-object v2, v0

    .line 52
    check-cast v2, Ll/e;

    .line 53
    .line 54
    :cond_3
    move-object v6, v2

    .line 55
    new-instance v3, Ld6/z0;

    .line 56
    .line 57
    const/4 v4, 0x2

    .line 58
    const/4 v9, 0x0

    .line 59
    move-object v5, p0

    .line 60
    move-object v8, p1

    .line 61
    move-object v7, p2

    .line 62
    invoke-direct/range {v3 .. v9}, Ld6/z0;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    .line 63
    .line 64
    .line 65
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 66
    .line 67
    .line 68
    move-result-wide p0

    .line 69
    const-wide/16 v4, 0xc8

    .line 70
    .line 71
    add-long/2addr p0, v4

    .line 72
    invoke-virtual {v1, v3, v8, p0, p1}, Landroid/os/Handler;->postAtTime(Ljava/lang/Runnable;Ljava/lang/Object;J)Z

    .line 73
    .line 74
    .line 75
    return-void
.end method

.method public r(I)Landroid/view/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lka/f0;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lka/f0;->u(I)Landroid/view/View;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public s(Landroid/view/View;)I
    .locals 1

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lka/g0;

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/View;->getBottom()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Lka/g0;

    .line 16
    .line 17
    iget-object p1, p1, Lka/g0;->b:Landroid/graphics/Rect;

    .line 18
    .line 19
    iget p1, p1, Landroid/graphics/Rect;->bottom:I

    .line 20
    .line 21
    add-int/2addr v0, p1

    .line 22
    iget p0, p0, Landroid/view/ViewGroup$MarginLayoutParams;->bottomMargin:I

    .line 23
    .line 24
    add-int/2addr v0, p0

    .line 25
    return v0
.end method

.method public t(FFFFFF)V
    .locals 7

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/ArrayList;

    .line 4
    .line 5
    new-instance v0, Lj3/s;

    .line 6
    .line 7
    move v1, p1

    .line 8
    move v2, p2

    .line 9
    move v3, p3

    .line 10
    move v4, p4

    .line 11
    move v5, p5

    .line 12
    move v6, p6

    .line 13
    invoke-direct/range {v0 .. v6}, Lj3/s;-><init>(FFFFFF)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lhu/q;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Lqr/y;

    .line 14
    .line 15
    invoke-static {p0}, Lmr/h;->a(Lqr/y;)Lqr/c0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-virtual {p0}, Lcom/google/crypto/tink/shaded/protobuf/x;->toString()Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x15
        :pswitch_0
    .end packed-switch
.end method

.method public u()J
    .locals 6

    .line 1
    sget v0, Le3/s;->j:I

    .line 2
    .line 3
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast p0, Landroid/os/Parcel;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/os/Parcel;->readLong()J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    const-wide/16 v2, 0x3f

    .line 12
    .line 13
    and-long/2addr v2, v0

    .line 14
    const-wide/16 v4, 0x10

    .line 15
    .line 16
    cmp-long p0, v2, v4

    .line 17
    .line 18
    if-gez p0, :cond_0

    .line 19
    .line 20
    return-wide v0

    .line 21
    :cond_0
    const-wide/16 v4, -0x40

    .line 22
    .line 23
    and-long/2addr v0, v4

    .line 24
    const-wide/16 v4, 0x1

    .line 25
    .line 26
    add-long/2addr v2, v4

    .line 27
    or-long/2addr v0, v2

    .line 28
    return-wide v0
.end method

.method public v()J
    .locals 4

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/os/Parcel;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/os/Parcel;->readByte()B

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x1

    .line 10
    const-wide/16 v2, 0x0

    .line 11
    .line 12
    if-ne v0, v1, :cond_0

    .line 13
    .line 14
    const-wide v0, 0x100000000L

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v1, 0x2

    .line 21
    if-ne v0, v1, :cond_1

    .line 22
    .line 23
    const-wide v0, 0x200000000L

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    move-wide v0, v2

    .line 30
    :goto_0
    invoke-static {v0, v1, v2, v3}, Lt4/p;->a(JJ)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    sget-wide v0, Lt4/o;->c:J

    .line 37
    .line 38
    return-wide v0

    .line 39
    :cond_2
    invoke-virtual {p0}, Landroid/os/Parcel;->readFloat()F

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    invoke-static {v0, v1, p0}, Lgq/b;->e(JF)J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    return-wide v0
.end method

.method public w([B[B)[B
    .locals 4

    .line 1
    :try_start_0
    invoke-virtual {p0, p1, p2}, Lhu/q;->x([B[B)[B

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/security/ProviderException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    move-exception v0

    .line 7
    const-string v1, "q"

    .line 8
    .line 9
    const-string v2, "encountered a potentially transient KeyStore error, will wait and retry"

    .line 10
    .line 11
    invoke-static {v1, v2, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 12
    .line 13
    .line 14
    invoke-static {}, Ljava/lang/Math;->random()D

    .line 15
    .line 16
    .line 17
    move-result-wide v0

    .line 18
    const-wide/high16 v2, 0x4059000000000000L    # 100.0

    .line 19
    .line 20
    mul-double/2addr v0, v2

    .line 21
    double-to-int v0, v0

    .line 22
    int-to-long v0, v0

    .line 23
    :try_start_1
    invoke-static {v0, v1}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_1

    .line 24
    .line 25
    .line 26
    :catch_1
    invoke-virtual {p0, p1, p2}, Lhu/q;->x([B[B)[B

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public x([B[B)[B
    .locals 4

    .line 1
    array-length v0, p1

    .line 2
    const/16 v1, 0x1c

    .line 3
    .line 4
    if-lt v0, v1, :cond_0

    .line 5
    .line 6
    new-instance v0, Ljavax/crypto/spec/GCMParameterSpec;

    .line 7
    .line 8
    const/16 v1, 0x80

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    const/16 v3, 0xc

    .line 12
    .line 13
    invoke-direct {v0, v1, p1, v2, v3}, Ljavax/crypto/spec/GCMParameterSpec;-><init>(I[BII)V

    .line 14
    .line 15
    .line 16
    const-string v1, "AES/GCM/NoPadding"

    .line 17
    .line 18
    invoke-static {v1}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Ljavax/crypto/SecretKey;

    .line 25
    .line 26
    const/4 v2, 0x2

    .line 27
    invoke-virtual {v1, v2, p0, v0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1, p2}, Ljavax/crypto/Cipher;->updateAAD([B)V

    .line 31
    .line 32
    .line 33
    array-length p0, p1

    .line 34
    sub-int/2addr p0, v3

    .line 35
    invoke-virtual {v1, p1, v3, p0}, Ljavax/crypto/Cipher;->doFinal([BII)[B

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :cond_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 41
    .line 42
    const-string p1, "ciphertext too short"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0
.end method

.method public y(Lka/a;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroidx/recyclerview/widget/RecyclerView;

    .line 4
    .line 5
    iget v0, p1, Lka/a;->a:I

    .line 6
    .line 7
    const/4 v1, 0x1

    .line 8
    if-eq v0, v1, :cond_3

    .line 9
    .line 10
    const/4 v1, 0x2

    .line 11
    if-eq v0, v1, :cond_2

    .line 12
    .line 13
    const/4 v1, 0x4

    .line 14
    if-eq v0, v1, :cond_1

    .line 15
    .line 16
    const/16 v1, 0x8

    .line 17
    .line 18
    if-eq v0, v1, :cond_0

    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iget-object p0, p0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 22
    .line 23
    iget v0, p1, Lka/a;->b:I

    .line 24
    .line 25
    iget p1, p1, Lka/a;->c:I

    .line 26
    .line 27
    invoke-virtual {p0, v0, p1}, Lka/f0;->a0(II)V

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    iget-object p0, p0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 32
    .line 33
    iget v0, p1, Lka/a;->b:I

    .line 34
    .line 35
    iget p1, p1, Lka/a;->c:I

    .line 36
    .line 37
    invoke-virtual {p0, v0, p1}, Lka/f0;->c0(II)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :cond_2
    iget-object p0, p0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 42
    .line 43
    iget v0, p1, Lka/a;->b:I

    .line 44
    .line 45
    iget p1, p1, Lka/a;->c:I

    .line 46
    .line 47
    invoke-virtual {p0, v0, p1}, Lka/f0;->b0(II)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_3
    iget-object p0, p0, Landroidx/recyclerview/widget/RecyclerView;->p:Lka/f0;

    .line 52
    .line 53
    iget v0, p1, Lka/a;->b:I

    .line 54
    .line 55
    iget p1, p1, Lka/a;->c:I

    .line 56
    .line 57
    invoke-virtual {p0, v0, p1}, Lka/f0;->Y(II)V

    .line 58
    .line 59
    .line 60
    return-void
.end method

.method public z([B[B)[B
    .locals 7

    .line 1
    array-length v0, p1

    .line 2
    const v1, 0x7fffffe3

    .line 3
    .line 4
    .line 5
    if-gt v0, v1, :cond_0

    .line 6
    .line 7
    array-length v0, p1

    .line 8
    add-int/lit8 v0, v0, 0x1c

    .line 9
    .line 10
    new-array v5, v0, [B

    .line 11
    .line 12
    const-string v0, "AES/GCM/NoPadding"

    .line 13
    .line 14
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Ljavax/crypto/SecretKey;

    .line 21
    .line 22
    const/4 v0, 0x1

    .line 23
    invoke-virtual {v1, v0, p0}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1, p2}, Ljavax/crypto/Cipher;->updateAAD([B)V

    .line 27
    .line 28
    .line 29
    array-length v4, p1

    .line 30
    const/16 v6, 0xc

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    move-object v2, p1

    .line 34
    invoke-virtual/range {v1 .. v6}, Ljavax/crypto/Cipher;->doFinal([BII[BI)I

    .line 35
    .line 36
    .line 37
    invoke-virtual {v1}, Ljavax/crypto/Cipher;->getIV()[B

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    const/16 p1, 0xc

    .line 42
    .line 43
    const/4 p2, 0x0

    .line 44
    invoke-static {p0, p2, v5, p2, p1}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 45
    .line 46
    .line 47
    return-object v5

    .line 48
    :cond_0
    new-instance p0, Ljava/security/GeneralSecurityException;

    .line 49
    .line 50
    const-string p1, "plaintext too long"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/security/GeneralSecurityException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0
.end method
