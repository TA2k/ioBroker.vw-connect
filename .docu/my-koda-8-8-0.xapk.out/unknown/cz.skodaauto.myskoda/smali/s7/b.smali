.class public Ls7/b;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Landroidx/fragment/app/m1;


# instance fields
.field public final d:Landroidx/collection/b1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Landroidx/fragment/app/m1;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Landroidx/fragment/app/m1;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ls7/b;->e:Landroidx/fragment/app/m1;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroidx/collection/b1;

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-direct {v0, v1}, Landroidx/collection/b1;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Ls7/b;->d:Landroidx/collection/b1;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final onCleared()V
    .locals 5

    .line 1
    invoke-super {p0}, Landroidx/lifecycle/b1;->onCleared()V

    .line 2
    .line 3
    .line 4
    iget-object p0, p0, Ls7/b;->d:Landroidx/collection/b1;

    .line 5
    .line 6
    invoke-virtual {p0}, Landroidx/collection/b1;->f()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x0

    .line 11
    if-gtz v0, :cond_1

    .line 12
    .line 13
    iget v0, p0, Landroidx/collection/b1;->g:I

    .line 14
    .line 15
    iget-object v2, p0, Landroidx/collection/b1;->f:[Ljava/lang/Object;

    .line 16
    .line 17
    move v3, v1

    .line 18
    :goto_0
    if-ge v3, v0, :cond_0

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    aput-object v4, v2, v3

    .line 22
    .line 23
    add-int/lit8 v3, v3, 0x1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    iput v1, p0, Landroidx/collection/b1;->g:I

    .line 27
    .line 28
    iput-boolean v1, p0, Landroidx/collection/b1;->d:Z

    .line 29
    .line 30
    return-void

    .line 31
    :cond_1
    invoke-virtual {p0, v1}, Landroidx/collection/b1;->h(I)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    .line 37
    .line 38
    new-instance p0, Ljava/lang/ClassCastException;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 41
    .line 42
    .line 43
    throw p0
.end method
