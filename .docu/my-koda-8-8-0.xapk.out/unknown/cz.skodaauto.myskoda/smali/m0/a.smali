.class public abstract Lm0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static volatile a:Ld01/x;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    sget-object v0, Lh0/r1;->c:Lh0/r1;

    .line 2
    .line 3
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    new-instance v2, Lb0/o1;

    .line 8
    .line 9
    const/4 v3, 0x3

    .line 10
    invoke-direct {v2, v3}, Lb0/o1;-><init>(I)V

    .line 11
    .line 12
    .line 13
    iget-object v0, v0, Lh0/r1;->a:Lf8/d;

    .line 14
    .line 15
    new-instance v3, Lh0/d0;

    .line 16
    .line 17
    const/4 v4, 0x1

    .line 18
    invoke-direct {v3, v2, v4}, Lh0/d0;-><init>(Ljava/lang/Object;I)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, v1, v3}, Lf8/d;->m(Ljava/util/concurrent/Executor;Lh0/l1;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
