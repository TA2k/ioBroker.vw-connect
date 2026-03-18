.class public final Ljp0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llp0/a;


# instance fields
.field public final a:Lyy0/c2;

.field public final b:Lyy0/l1;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iput-object v0, p0, Ljp0/a;->a:Lyy0/c2;

    .line 10
    .line 11
    new-instance v1, Lyy0/l1;

    .line 12
    .line 13
    invoke-direct {v1, v0}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 14
    .line 15
    .line 16
    iput-object v1, p0, Ljp0/a;->b:Lyy0/l1;

    .line 17
    .line 18
    return-void
.end method
