.class public final La8/h1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements La8/a1;


# instance fields
.field public final a:Lh8/w;

.field public final b:Ljava/lang/Object;

.field public final c:Ljava/util/ArrayList;

.field public d:I

.field public e:Z


# direct methods
.method public constructor <init>(Lh8/a;Z)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lh8/w;

    .line 5
    .line 6
    invoke-direct {v0, p1, p2}, Lh8/w;-><init>(Lh8/a;Z)V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, La8/h1;->a:Lh8/w;

    .line 10
    .line 11
    new-instance p1, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, La8/h1;->c:Ljava/util/ArrayList;

    .line 17
    .line 18
    new-instance p1, Ljava/lang/Object;

    .line 19
    .line 20
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object p1, p0, La8/h1;->b:Ljava/lang/Object;

    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, La8/h1;->b:Ljava/lang/Object;

    .line 2
    .line 3
    return-object p0
.end method

.method public final b()Lt7/p0;
    .locals 0

    .line 1
    iget-object p0, p0, La8/h1;->a:Lh8/w;

    .line 2
    .line 3
    iget-object p0, p0, Lh8/w;->o:Lh8/u;

    .line 4
    .line 5
    return-object p0
.end method
