.class public final Lry0/h;
.super Lry0/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqy0/b;


# static fields
.field public static final e:Lry0/h;


# instance fields
.field public final d:[Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lry0/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v1, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0, v1}, Lry0/h;-><init>([Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lry0/h;->e:Lry0/h;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>([Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lry0/h;->d:[Ljava/lang/Object;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final c()I
    .locals 0

    .line 1
    iget-object p0, p0, Lry0/h;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length p0, p0

    .line 4
    return p0
.end method

.method public final e()Lry0/e;
    .locals 4

    .line 1
    new-instance v0, Lry0/e;

    .line 2
    .line 3
    iget-object v1, p0, Lry0/h;->d:[Ljava/lang/Object;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, p0, v3, v1, v2}, Lry0/e;-><init>(Lry0/a;[Ljava/lang/Object;[Ljava/lang/Object;I)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    .line 1
    invoke-virtual {p0}, Lry0/h;->c()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1, v0}, Llp/qa;->d(II)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lry0/h;->d:[Ljava/lang/Object;

    .line 9
    .line 10
    aget-object p0, p0, p1

    .line 11
    .line 12
    return-object p0
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lry0/h;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {p1, p0}, Lmx0/n;->D(Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 0

    .line 1
    iget-object p0, p0, Lry0/h;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    invoke-static {p1, p0}, Lmx0/n;->J(Ljava/lang/Object;[Ljava/lang/Object;)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 2

    .line 1
    iget-object p0, p0, Lry0/h;->d:[Ljava/lang/Object;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    invoke-static {p1, v0}, Llp/qa;->e(II)V

    .line 5
    .line 6
    .line 7
    new-instance v0, Lry0/b;

    .line 8
    .line 9
    array-length v1, p0

    .line 10
    invoke-direct {v0, p0, p1, v1}, Lry0/b;-><init>([Ljava/lang/Object;II)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method
