.class public final Le3/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/z1;


# instance fields
.field public final d:Le3/w;

.field public final e:Lh3/c;


# direct methods
.method public constructor <init>(Le3/w;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le3/x;->d:Le3/w;

    .line 5
    .line 6
    invoke-interface {p1}, Le3/w;->a()Lh3/c;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Le3/x;->e:Lh3/c;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final c()V
    .locals 0

    .line 1
    return-void
.end method

.method public final e()V
    .locals 1

    .line 1
    iget-object v0, p0, Le3/x;->d:Le3/w;

    .line 2
    .line 3
    iget-object p0, p0, Le3/x;->e:Lh3/c;

    .line 4
    .line 5
    invoke-interface {v0, p0}, Le3/w;->b(Lh3/c;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public final h()V
    .locals 1

    .line 1
    iget-object v0, p0, Le3/x;->d:Le3/w;

    .line 2
    .line 3
    iget-object p0, p0, Le3/x;->e:Lh3/c;

    .line 4
    .line 5
    invoke-interface {v0, p0}, Le3/w;->b(Lh3/c;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
