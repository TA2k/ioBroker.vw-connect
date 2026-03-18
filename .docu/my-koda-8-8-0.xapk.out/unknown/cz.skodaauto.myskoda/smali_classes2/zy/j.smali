.class public final Lzy/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lxy/e;


# direct methods
.method public constructor <init>(Lxy/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzy/j;->a:Lxy/e;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    iget-object p0, p0, Lzy/j;->a:Lxy/e;

    .line 4
    .line 5
    new-instance v0, Laz/i;

    .line 6
    .line 7
    iget-object v1, p0, Lxy/e;->b:Laz/d;

    .line 8
    .line 9
    iget-object v2, p0, Lxy/e;->c:Laz/d;

    .line 10
    .line 11
    iget-object v3, p0, Lxy/e;->d:Ljava/util/ArrayList;

    .line 12
    .line 13
    iget v4, p0, Lxy/e;->h:I

    .line 14
    .line 15
    iget-object v5, p0, Lxy/e;->e:Ljava/util/ArrayList;

    .line 16
    .line 17
    iget-object v6, p0, Lxy/e;->f:Laz/h;

    .line 18
    .line 19
    iget-boolean v7, p0, Lxy/e;->g:Z

    .line 20
    .line 21
    iget-boolean v8, p0, Lxy/e;->i:Z

    .line 22
    .line 23
    invoke-direct/range {v0 .. v8}, Laz/i;-><init>(Laz/d;Laz/d;Ljava/util/List;ILjava/util/List;Laz/h;ZZ)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method
