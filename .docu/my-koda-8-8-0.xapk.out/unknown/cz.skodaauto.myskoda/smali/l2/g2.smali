.class public final Ll2/g2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Iterable;
.implements Lby0/a;


# instance fields
.field public final d:Ll2/f2;

.field public final e:I

.field public final f:I


# direct methods
.method public constructor <init>(Ll2/f2;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/g2;->d:Ll2/f2;

    .line 5
    .line 6
    iput p2, p0, Ll2/g2;->e:I

    .line 7
    .line 8
    iput p3, p0, Ll2/g2;->f:I

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 4

    .line 1
    iget-object v0, p0, Ll2/g2;->d:Ll2/f2;

    .line 2
    .line 3
    iget v1, v0, Ll2/f2;->k:I

    .line 4
    .line 5
    iget v2, p0, Ll2/g2;->f:I

    .line 6
    .line 7
    if-eq v1, v2, :cond_0

    .line 8
    .line 9
    invoke-static {}, Ll2/h2;->f()V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget p0, p0, Ll2/g2;->e:I

    .line 13
    .line 14
    invoke-virtual {v0, p0}, Ll2/f2;->m(I)Ll2/p0;

    .line 15
    .line 16
    .line 17
    new-instance v1, Ll2/o0;

    .line 18
    .line 19
    add-int/lit8 v2, p0, 0x1

    .line 20
    .line 21
    iget-object v3, v0, Ll2/f2;->d:[I

    .line 22
    .line 23
    invoke-static {p0, v3}, Ll2/h2;->a(I[I)I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    add-int/2addr v3, p0

    .line 28
    invoke-direct {v1, v0, v2, v3}, Ll2/o0;-><init>(Ll2/f2;II)V

    .line 29
    .line 30
    .line 31
    return-object v1
.end method
