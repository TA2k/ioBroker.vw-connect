.class public final Lh8/u;
.super Lh8/q;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final e:Ljava/lang/Object;


# instance fields
.field public final c:Ljava/lang/Object;

.field public final d:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lh8/u;->e:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lt7/p0;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lh8/q;-><init>(Lt7/p0;)V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lh8/u;->c:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p3, p0, Lh8/u;->d:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Ljava/lang/Object;)I
    .locals 1

    .line 1
    sget-object v0, Lh8/u;->e:Ljava/lang/Object;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lh8/u;->d:Ljava/lang/Object;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    move-object p1, v0

    .line 14
    :cond_0
    iget-object p0, p0, Lh8/q;->b:Lt7/p0;

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Lt7/p0;->b(Ljava/lang/Object;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0
.end method

.method public final f(ILt7/n0;Z)Lt7/n0;
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/q;->b:Lt7/p0;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2, p3}, Lt7/p0;->f(ILt7/n0;Z)Lt7/n0;

    .line 4
    .line 5
    .line 6
    iget-object p1, p2, Lt7/n0;->b:Ljava/lang/Object;

    .line 7
    .line 8
    iget-object p0, p0, Lh8/u;->d:Ljava/lang/Object;

    .line 9
    .line 10
    invoke-static {p1, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    if-eqz p3, :cond_0

    .line 17
    .line 18
    sget-object p0, Lh8/u;->e:Ljava/lang/Object;

    .line 19
    .line 20
    iput-object p0, p2, Lt7/n0;->b:Ljava/lang/Object;

    .line 21
    .line 22
    :cond_0
    return-object p2
.end method

.method public final l(I)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/q;->b:Lt7/p0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Lt7/p0;->l(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iget-object p0, p0, Lh8/u;->d:Ljava/lang/Object;

    .line 8
    .line 9
    invoke-static {p1, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    sget-object p0, Lh8/u;->e:Ljava/lang/Object;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_0
    return-object p1
.end method

.method public final m(ILt7/o0;J)Lt7/o0;
    .locals 1

    .line 1
    iget-object v0, p0, Lh8/q;->b:Lt7/p0;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2, p3, p4}, Lt7/p0;->m(ILt7/o0;J)Lt7/o0;

    .line 4
    .line 5
    .line 6
    iget-object p1, p2, Lt7/o0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    iget-object p0, p0, Lh8/u;->c:Ljava/lang/Object;

    .line 9
    .line 10
    invoke-static {p1, p0}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    sget-object p0, Lt7/o0;->p:Ljava/lang/Object;

    .line 17
    .line 18
    iput-object p0, p2, Lt7/o0;->a:Ljava/lang/Object;

    .line 19
    .line 20
    :cond_0
    return-object p2
.end method
