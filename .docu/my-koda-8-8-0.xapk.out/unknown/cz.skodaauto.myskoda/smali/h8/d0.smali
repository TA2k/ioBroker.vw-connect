.class public final synthetic Lh8/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/f;


# instance fields
.field public final synthetic d:Ld8/f;

.field public final synthetic e:Lh8/s;

.field public final synthetic f:Lh8/x;

.field public final synthetic g:I


# direct methods
.method public synthetic constructor <init>(Ld8/f;Lh8/s;Lh8/x;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lh8/d0;->d:Ld8/f;

    .line 5
    .line 6
    iput-object p2, p0, Lh8/d0;->e:Lh8/s;

    .line 7
    .line 8
    iput-object p3, p0, Lh8/d0;->f:Lh8/x;

    .line 9
    .line 10
    iput p4, p0, Lh8/d0;->g:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 6

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lh8/h0;

    .line 3
    .line 4
    iget-object p1, p0, Lh8/d0;->d:Ld8/f;

    .line 5
    .line 6
    iget v1, p1, Ld8/f;->a:I

    .line 7
    .line 8
    iget-object v2, p1, Ld8/f;->b:Lh8/b0;

    .line 9
    .line 10
    iget-object v3, p0, Lh8/d0;->e:Lh8/s;

    .line 11
    .line 12
    iget-object v4, p0, Lh8/d0;->f:Lh8/x;

    .line 13
    .line 14
    iget v5, p0, Lh8/d0;->g:I

    .line 15
    .line 16
    invoke-interface/range {v0 .. v5}, Lh8/h0;->c(ILh8/b0;Lh8/s;Lh8/x;I)V

    .line 17
    .line 18
    .line 19
    return-void
.end method
