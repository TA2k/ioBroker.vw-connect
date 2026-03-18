.class public final synthetic La8/e1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic d:La8/f1;

.field public final synthetic e:Landroid/util/Pair;

.field public final synthetic f:Lh8/s;

.field public final synthetic g:Lh8/x;

.field public final synthetic h:Ljava/io/IOException;

.field public final synthetic i:Z


# direct methods
.method public synthetic constructor <init>(La8/f1;Landroid/util/Pair;Lh8/s;Lh8/x;Ljava/io/IOException;Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, La8/e1;->d:La8/f1;

    .line 5
    .line 6
    iput-object p2, p0, La8/e1;->e:Landroid/util/Pair;

    .line 7
    .line 8
    iput-object p3, p0, La8/e1;->f:Lh8/s;

    .line 9
    .line 10
    iput-object p4, p0, La8/e1;->g:Lh8/x;

    .line 11
    .line 12
    iput-object p5, p0, La8/e1;->h:Ljava/io/IOException;

    .line 13
    .line 14
    iput-boolean p6, p0, La8/e1;->i:Z

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    .line 1
    iget-object v0, p0, La8/e1;->d:La8/f1;

    .line 2
    .line 3
    iget-object v0, v0, La8/f1;->e:Lac/i;

    .line 4
    .line 5
    iget-object v0, v0, Lac/i;->i:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lb8/e;

    .line 9
    .line 10
    iget-object v0, p0, La8/e1;->e:Landroid/util/Pair;

    .line 11
    .line 12
    iget-object v2, v0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Ljava/lang/Integer;

    .line 15
    .line 16
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    iget-object v0, v0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 21
    .line 22
    move-object v3, v0

    .line 23
    check-cast v3, Lh8/b0;

    .line 24
    .line 25
    iget-object v4, p0, La8/e1;->f:Lh8/s;

    .line 26
    .line 27
    iget-object v5, p0, La8/e1;->g:Lh8/x;

    .line 28
    .line 29
    iget-object v6, p0, La8/e1;->h:Ljava/io/IOException;

    .line 30
    .line 31
    iget-boolean v7, p0, La8/e1;->i:Z

    .line 32
    .line 33
    invoke-virtual/range {v1 .. v7}, Lb8/e;->e(ILh8/b0;Lh8/s;Lh8/x;Ljava/io/IOException;Z)V

    .line 34
    .line 35
    .line 36
    return-void
.end method
