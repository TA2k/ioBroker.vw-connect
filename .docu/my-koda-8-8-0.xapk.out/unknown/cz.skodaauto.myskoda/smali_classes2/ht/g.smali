.class public final Lht/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lht/i;


# instance fields
.field public final a:Laq/k;


# direct methods
.method public constructor <init>(Laq/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lht/g;->a:Laq/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Exception;)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final b(Ljt/b;)Z
    .locals 2

    .line 1
    iget v0, p1, Ljt/b;->b:I

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v1, 0x4

    .line 8
    if-ne v0, v1, :cond_1

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_1
    const/4 v1, 0x5

    .line 12
    if-ne v0, v1, :cond_2

    .line 13
    .line 14
    :goto_0
    iget-object p0, p0, Lht/g;->a:Laq/k;

    .line 15
    .line 16
    iget-object p1, p1, Ljt/b;->a:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Laq/k;->d(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_2
    const/4 p0, 0x0

    .line 24
    return p0
.end method
