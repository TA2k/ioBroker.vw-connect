.class public final Lc8/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final d:Lc8/h;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lc8/g;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Lc8/g;->a()Lc8/h;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lc8/h;->d:Lc8/h;

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Lc8/g;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-boolean v0, p1, Lc8/g;->a:Z

    .line 5
    .line 6
    iput-boolean v0, p0, Lc8/h;->a:Z

    .line 7
    .line 8
    iget-boolean v0, p1, Lc8/g;->b:Z

    .line 9
    .line 10
    iput-boolean v0, p0, Lc8/h;->b:Z

    .line 11
    .line 12
    iget-boolean p1, p1, Lc8/g;->c:Z

    .line 13
    .line 14
    iput-boolean p1, p0, Lc8/h;->c:Z

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    if-eqz p1, :cond_2

    .line 5
    .line 6
    const-class v0, Lc8/h;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-eq v0, v1, :cond_1

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    check-cast p1, Lc8/h;

    .line 16
    .line 17
    iget-boolean v0, p0, Lc8/h;->a:Z

    .line 18
    .line 19
    iget-boolean v1, p1, Lc8/h;->a:Z

    .line 20
    .line 21
    if-ne v0, v1, :cond_2

    .line 22
    .line 23
    iget-boolean v0, p0, Lc8/h;->b:Z

    .line 24
    .line 25
    iget-boolean v1, p1, Lc8/h;->b:Z

    .line 26
    .line 27
    if-ne v0, v1, :cond_2

    .line 28
    .line 29
    iget-boolean p0, p0, Lc8/h;->c:Z

    .line 30
    .line 31
    iget-boolean p1, p1, Lc8/h;->c:Z

    .line 32
    .line 33
    if-ne p0, p1, :cond_2

    .line 34
    .line 35
    :goto_0
    const/4 p0, 0x1

    .line 36
    return p0

    .line 37
    :cond_2
    :goto_1
    const/4 p0, 0x0

    .line 38
    return p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-boolean v0, p0, Lc8/h;->a:Z

    .line 2
    .line 3
    shl-int/lit8 v0, v0, 0x2

    .line 4
    .line 5
    iget-boolean v1, p0, Lc8/h;->b:Z

    .line 6
    .line 7
    shl-int/lit8 v1, v1, 0x1

    .line 8
    .line 9
    add-int/2addr v0, v1

    .line 10
    iget-boolean p0, p0, Lc8/h;->c:Z

    .line 11
    .line 12
    add-int/2addr v0, p0

    .line 13
    return v0
.end method
