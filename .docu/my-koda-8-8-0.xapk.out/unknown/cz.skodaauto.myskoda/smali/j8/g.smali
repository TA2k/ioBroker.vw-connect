.class public final Lj8/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Comparable;


# instance fields
.field public final d:Z

.field public final e:Z


# direct methods
.method public constructor <init>(Lt7/o;I)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget p1, p1, Lt7/o;->e:I

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    and-int/2addr p1, v0

    .line 8
    const/4 v1, 0x0

    .line 9
    if-eqz p1, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    move v0, v1

    .line 13
    :goto_0
    iput-boolean v0, p0, Lj8/g;->d:Z

    .line 14
    .line 15
    invoke-static {p2, v1}, La8/f;->n(IZ)Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    iput-boolean p1, p0, Lj8/g;->e:Z

    .line 20
    .line 21
    return-void
.end method


# virtual methods
.method public final compareTo(Ljava/lang/Object;)I
    .locals 3

    .line 1
    check-cast p1, Lj8/g;

    .line 2
    .line 3
    iget-boolean v0, p0, Lj8/g;->e:Z

    .line 4
    .line 5
    iget-boolean v1, p1, Lj8/g;->e:Z

    .line 6
    .line 7
    sget-object v2, Lhr/z;->a:Lhr/x;

    .line 8
    .line 9
    invoke-virtual {v2, v0, v1}, Lhr/x;->c(ZZ)Lhr/z;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    iget-boolean p0, p0, Lj8/g;->d:Z

    .line 14
    .line 15
    iget-boolean p1, p1, Lj8/g;->d:Z

    .line 16
    .line 17
    invoke-virtual {v0, p0, p1}, Lhr/z;->c(ZZ)Lhr/z;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p0}, Lhr/z;->e()I

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0
.end method
