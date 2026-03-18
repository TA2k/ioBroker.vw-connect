.class public final enum Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "b"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b$a;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;",
        ">;"
    }
.end annotation


# static fields
.field public static final c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b$a;

.field public static final enum d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

.field public static final enum e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

.field private static final synthetic f:[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

.field private static final synthetic g:Lsx0/a;


# instance fields
.field private final b:I


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 2
    .line 3
    const-string v1, "PUSH"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x1

    .line 7
    invoke-direct {v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;-><init>(Ljava/lang/String;II)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 11
    .line 12
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 13
    .line 14
    const-string v1, "ALERT_INBOX"

    .line 15
    .line 16
    const/4 v2, 0x3

    .line 17
    invoke-direct {v0, v1, v3, v2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;-><init>(Ljava/lang/String;II)V

    .line 18
    .line 19
    .line 20
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 21
    .line 22
    invoke-static {}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->a()[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->f:[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 27
    .line 28
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->g:Lsx0/a;

    .line 33
    .line 34
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b$a;

    .line 35
    .line 36
    const/4 v1, 0x0

    .line 37
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->c:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b$a;

    .line 41
    .line 42
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;II)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(I)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput p3, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->b:I

    .line 5
    .line 6
    return-void
.end method

.method private static final synthetic a()[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->d:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->e:Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 4
    .line 5
    filled-new-array {v0, v1}, [Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method public static b()Lsx0/a;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lsx0/a;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->g:Lsx0/a;

    .line 2
    .line 3
    return-object v0
.end method

.method public static valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;
    .locals 1

    .line 1
    const-class v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->f:[Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 2
    .line 3
    invoke-virtual {v0}, [Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public final c()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->b:I

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage$b;->b:I

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
