.class public final synthetic Lfb/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lfb/b;


# instance fields
.field public final synthetic d:Ljava/util/concurrent/Executor;

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Leb/b;

.field public final synthetic g:Landroidx/work/impl/WorkDatabase;


# direct methods
.method public synthetic constructor <init>(Ljava/util/concurrent/Executor;Ljava/util/List;Leb/b;Landroidx/work/impl/WorkDatabase;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfb/h;->d:Ljava/util/concurrent/Executor;

    .line 5
    .line 6
    iput-object p2, p0, Lfb/h;->e:Ljava/util/List;

    .line 7
    .line 8
    iput-object p3, p0, Lfb/h;->f:Leb/b;

    .line 9
    .line 10
    iput-object p4, p0, Lfb/h;->g:Landroidx/work/impl/WorkDatabase;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final b(Lmb/i;Z)V
    .locals 6

    .line 1
    new-instance v0, Lc8/r;

    .line 2
    .line 3
    const/4 v5, 0x1

    .line 4
    iget-object v1, p0, Lfb/h;->e:Ljava/util/List;

    .line 5
    .line 6
    iget-object v3, p0, Lfb/h;->f:Leb/b;

    .line 7
    .line 8
    iget-object v4, p0, Lfb/h;->g:Landroidx/work/impl/WorkDatabase;

    .line 9
    .line 10
    move-object v2, p1

    .line 11
    invoke-direct/range {v0 .. v5}, Lc8/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lfb/h;->d:Ljava/util/concurrent/Executor;

    .line 15
    .line 16
    invoke-interface {p0, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method
