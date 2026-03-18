.class public abstract Lcom/salesforce/marketingcloud/events/predicates/h;
.super Lcom/salesforce/marketingcloud/events/predicates/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Lcom/salesforce/marketingcloud/events/predicates/f;"
    }
.end annotation


# static fields
.field private static final i:Ljava/lang/String;


# instance fields
.field private final e:Ljava/lang/Object;

.field private final f:Lcom/salesforce/marketingcloud/events/g$a;

.field private final g:Ljava/lang/Object;

.field private final h:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "ValuePredicate"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/events/predicates/h;->i:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/events/predicates/f;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/predicates/h;->e:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/events/predicates/h;->f:Lcom/salesforce/marketingcloud/events/g$a;

    .line 7
    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/events/predicates/h;->g:Ljava/lang/Object;

    .line 9
    .line 10
    filled-new-array {p1, p2, p3}, [Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    const-string p2, "%s %s %s"

    .line 15
    .line 16
    invoke-static {p2, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    iput-object p1, p0, Lcom/salesforce/marketingcloud/events/predicates/h;->h:Ljava/lang/String;

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public abstract a(Ljava/lang/Object;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Object;",
            ")TT;"
        }
    .end annotation
.end method

.method public final a()Z
    .locals 4

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/events/predicates/h;->e:Ljava/lang/Object;

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/events/predicates/h;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Lcom/salesforce/marketingcloud/events/predicates/h;->f:Lcom/salesforce/marketingcloud/events/g$a;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/events/predicates/h;->g:Ljava/lang/Object;

    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/events/predicates/h;->a(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {p0, v0, v1, v2}, Lcom/salesforce/marketingcloud/events/predicates/h;->a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)Z

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p0

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/events/predicates/h;->i:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v2, v1, [Ljava/lang/Object;

    const-string v3, "Unable to evaluate predicate.  Returning default value of \'false\'"

    invoke-static {v0, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1
.end method

.method public abstract a(Ljava/lang/Object;Lcom/salesforce/marketingcloud/events/g$a;Ljava/lang/Object;)Z
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;",
            "Lcom/salesforce/marketingcloud/events/g$a;",
            "TT;)Z"
        }
    .end annotation
.end method

.method public c()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/events/predicates/h;->h:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method
