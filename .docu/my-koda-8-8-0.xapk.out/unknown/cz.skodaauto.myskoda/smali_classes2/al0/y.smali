.class public final Lal0/y;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lqf0/g;

.field public final b:Lal0/c0;


# direct methods
.method public constructor <init>(Lqf0/g;Lal0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lal0/y;->a:Lqf0/g;

    .line 5
    .line 6
    iput-object p2, p0, Lal0/y;->b:Lal0/c0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, La50/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x4

    .line 5
    invoke-direct {v0, p0, v1, v2}, La50/c;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 6
    .line 7
    .line 8
    new-instance p0, Lyy0/m1;

    .line 9
    .line 10
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 11
    .line 12
    .line 13
    return-object p0
.end method
