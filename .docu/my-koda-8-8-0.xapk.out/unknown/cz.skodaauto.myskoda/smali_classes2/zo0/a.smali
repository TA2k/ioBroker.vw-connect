.class public final Lzo0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lzo0/k;


# direct methods
.method public constructor <init>(Lzo0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzo0/a;->a:Lzo0/k;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Ljava/time/OffsetDateTime;

    .line 2
    .line 3
    iget-object p0, p0, Lzo0/a;->a:Lzo0/k;

    .line 4
    .line 5
    check-cast p0, Lwo0/a;

    .line 6
    .line 7
    iget-object p2, p0, Lwo0/a;->a:Ljava/time/OffsetDateTime;

    .line 8
    .line 9
    iput-object p1, p0, Lwo0/a;->a:Ljava/time/OffsetDateTime;

    .line 10
    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    invoke-virtual {p2, p1}, Ljava/time/OffsetDateTime;->isBefore(Ljava/time/OffsetDateTime;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x1

    .line 19
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0
.end method
